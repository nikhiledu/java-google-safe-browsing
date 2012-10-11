package com.gsbcrawler;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.gsbcrawler.gsb.GSBURLUtil;
import com.gsbcrawler.gsb.models.GSBArray;
import com.gsbcrawler.gsb.models.GSBModeEnum;
import com.gsbcrawler.gsb.models.GSBPairs;
import com.gsbcrawler.gsb.models.GSBTmpArray;
import com.gsbcrawler.util.Utils;

/**
 * Fill a database with GSB's datas
 * @author Julien Sosin <jsosin@domaintools.com>
 */
public class GSBCrawler {

	//GSB
	private static List<GSBListEnum> listGSB;
	private String gsbUrl = "http://safebrowsing.clients.google.com/safebrowsing";
	private String gsbKey = "";
	private static String gsbPhishingList = "googpub-phish-shavar";
	private static String gsbMalwareList = "goog-malware-shavar";
	private String gsbAppVersion = "1.5.2";
	private String gsbApiVersion = "2.2";

	//Database
	private Connection con;
	private String dbUrl;
	private String dbUsername;
	private String dbPassword;
	private static String dbPrefix = "";

	//Workspace
	private String path = "";
	private String pingFilePath = "";
	private String fileNextCheck = "nextcheck.dat";
	private String fileNextCheckl = "nextcheckl.dat";

	private static List<List<Map<Integer,Boolean>>> mainList;
	
	private enum GSBListEnum {

		GSB_PHISHING(0,dbPrefix+gsbPhishingList),
		GSB_MALWARE(1,dbPrefix+gsbMalwareList);
		
		private final int id;
		private final String name;
		
		private GSBListEnum(int id, String name) {
			this.id = id;
			this.name = name;
		}

		public int getId() {
			return id;
		}

		public String getName() {
			return name;
		}
	}
	
	/**
	 * Create a Wrapper to use Google Safe Browinsg.
	 * This wrapper allows to use your GSB's database to looking for some malware/phishing website
	 * @param gsbKey : The key provided by GSB
	 * @param dbPrefix : Prefix you will use in YOUR database
	 * @param path : Path where the wrapper will create files
	 * @param dbUrl : The database url use by jdbc Example : jdbc:mysql://localhost/gsb
	 * @param dbUsername : The database's username
	 * @param dbPassword : The database's password
	 */
	public GSBCrawler(String gsbKey, String dbPrefix, String path, String dbUrl, String dbUsername, String dbPassword){
		createGSBList();
		this.gsbKey = gsbKey;
		this.dbPrefix = dbPrefix;
		this.path = path;
		this.dbUrl = dbUrl;
		this.dbUsername = dbUsername;
		this.dbPassword = dbPassword;
		try {
			con = DriverManager.getConnection (this.dbUrl,this.dbUsername,this.dbPassword);
			Class.forName("com.mysql.jdbc.Driver");
		} catch (SQLException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
		generateDatabase();
	}

	/**
	 * Update the GSB's databses
	 * @return the number of seconds to wait before the next request
	 */
	public Integer updateDB() {
		Integer res=-1;
		res = runUpdate(con);
		return res;
	}

	private void init() {          
		createFiles();
		mainList = new ArrayList<List<Map<Integer,Boolean>>>();
		//AddList
		mainList.add(GSBModeEnum.GSB_ADD.getId(),new ArrayList<Map<Integer,Boolean>>());
		mainList.get(GSBModeEnum.GSB_ADD.getId()).add(new Hashtable<Integer,Boolean>());
		mainList.get(GSBModeEnum.GSB_ADD.getId()).add(new Hashtable<Integer,Boolean>());
		//SubList
		mainList.add(GSBModeEnum.GSB_SUB.getId(),new ArrayList<Map<Integer,Boolean>>());
		mainList.get(GSBModeEnum.GSB_SUB.getId()).add(new Hashtable<Integer,Boolean>());
		mainList.get(GSBModeEnum.GSB_SUB.getId()).add(new Hashtable<Integer,Boolean>());
	}

	/**
	 * Create files needed to stock some datas
	 */
	private void createFiles() {
		File nextCheck = new File(path+pingFilePath+fileNextCheck);
		File nextCheckl = new File(path+pingFilePath+fileNextCheckl);
		try {
			if(!nextCheck.exists()) {
				nextCheck.createNewFile();
			}
			if(!nextCheckl.exists()) {
				nextCheckl.createNewFile();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Try to update the database
	 * @param con the connection
	 * @return number of seconds to wait before the next update
	 */
	private Integer runUpdate(Connection con) {
		this.con = con;
		StringBuilder body = new StringBuilder();
		init();
		int wait = 180000;
		wait = checkTimeout("data");
		if(wait == 0) {
			for(GSBListEnum gsbenum : getListGSB()) {
				body.append(formattedRequest(gsbenum));
			}
			getData(body.toString());
			wait = checkTimeout("data");
		}
		return wait;
	}

	/**
	 * Format a full request body for a desired list including
	 * name and full ranges for add and sub
	 **/
	private String formattedRequest(GSBListEnum gsbList){
		List<List<String>> fullranges = getFullRanges(gsbList);
		StringBuilder buildpart = new StringBuilder();
		buildpart.append(gsbList.getName()+";");
		if(fullranges.get(GSBModeEnum.GSB_SUB.getId()).size()>0) {
			buildpart.append("s:"+GSBURLUtil.implode(fullranges.get(GSBModeEnum.GSB_SUB.getId()).toArray(),","));
		}
		if(fullranges.get(GSBModeEnum.GSB_SUB.getId()).size()>0&&fullranges.get(GSBModeEnum.GSB_ADD.getId()).size()>0) {
			buildpart.append(":");
		}

		if(fullranges.get(GSBModeEnum.GSB_ADD.getId()).size()>0) {
			buildpart.append("a:"+GSBURLUtil.implode(fullranges.get(GSBModeEnum.GSB_ADD.getId()).toArray(),","));
		}
		buildpart.append("\n");
		return buildpart.toString();
	}

	/**
	 * Get both add and sub ranges for a requested list
	 **/
	private List<List<String>> getFullRanges(GSBListEnum gsbList){
		List<List<String>> res = new ArrayList<List<String>>();
		List<String> lista = getRanges(gsbList, GSBModeEnum.GSB_ADD);
		List<String> lists = getRanges(gsbList, GSBModeEnum.GSB_SUB);
		res.add(lista);
		res.add(lists);
		return res;		
	}

	/**
	 * Get ranges of existing chunks from a requested list
	 * and type (add [a] or sub [s] return them and set
	 * mainlist to received for that chunk (prevent dupes)
	 * @return ranges
	 */
	private List<String> getRanges(GSBListEnum gsbList, GSBModeEnum mode){
		List<String> ranges = new ArrayList<String>();
		int i = 0;
		int start=0;
		int previous=0;
		int expected=0;
		String checktable = gsbList.getName()+"-"+mode.getName()+"-index";
		String SQL_QUERY ="SELECT ChunkNum FROM `"+dbPrefix+checktable+"` ORDER BY `ChunkNum` ASC";
		Statement stmt;
		try {
			stmt = con.createStatement();
			ResultSet rs = stmt.executeQuery(SQL_QUERY);
			int chunkNum = 0;
			while (rs.next()) {
				chunkNum = rs.getInt("ChunkNum");
				mainList.get(mode.getId()).get(gsbList.getId()).put(chunkNum,true);
				if(i == 0) {
					start = chunkNum;
					previous = chunkNum;
				}
				else {
					expected = previous + 1;
					if(chunkNum != expected) {
						if(start == previous) {
							ranges.add(String.valueOf(start));
						}
						else {
							ranges.add(start+"-"+previous);
						}
						start = chunkNum;
					}
					previous = chunkNum;
				}
				i++;
			}
		} catch (SQLException e) {
			e.printStackTrace();
		}
		if(start>0&&previous>0) {
			if(start == previous) {
				ranges.add(String.valueOf(start));
			}
			else {
				ranges.add(start+"-"+previous);
			}
		}
		return ranges;
	}

	/**
	 * Checks timeout in timeout files (usually performed at the
	 * start of script)
	 **/
	private int checkTimeout(String type){
		int res = 180000;
		String file;
		long curstatus;
		long timestamp = System.currentTimeMillis()/1000;
		if(type=="data") {
			file = "nextcheck.dat";
		}	
		else {
			file = "nextcheckl.dat";
		}
		try {
			String curstatusString = readFileAsString(pingFilePath+file).split("\\|\\|")[0];
			curstatus = Long.valueOf(curstatusString);
			if(timestamp<curstatus){
				res = (int) (curstatus-timestamp);
			}
			else {
				//Allowed to request
				res = 0;
			}
		} catch (NumberFormatException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return res;
	}


	/**
	 * Processes data recieved from a GSB data request into a managable array
	 * @return 
	 **/
	private boolean  processChunks(List<Integer> cloneData, String listname){
		ArrayList<GSBTmpArray> tmparray;
		List<List<Integer>> splitHead;
		String[] chunkInfo;
		String type;
		List<Integer> chunkData = new ArrayList<Integer>();
		int chunkNum;
		int hashLen = 0;
		int chunkLen = 0;
		int maini = 0;
		int realCount;
		int addChunkNum;
		String prefix = "";
		String hostKey = "";
		String count = "";
		while(cloneData.size()>0){
			splitHead = Utils.splitList(cloneData,'\n',2);
			chunkInfo = Utils.listInt2String(splitHead.get(0)).split(":");
			type = chunkInfo[0];
			chunkNum = Integer.valueOf(chunkInfo[1]);
			hashLen = Integer.valueOf(chunkInfo[2]);
			chunkLen = Integer.valueOf(chunkInfo[3]);
			if(chunkLen>0) {
				tmparray = new ArrayList<GSBTmpArray>();
				chunkData = splitHead.get(1).subList(0, chunkLen);
				maini = 0;
				if(type.equals("a")) {
					while(chunkData.size()>0) {
						hostKey = Utils.getHexFromUnsignedByteList(chunkData,0,4);
						count = Utils.getHexFromUnsignedByteList(chunkData,4);
						tmparray.add(new GSBTmpArray(hostKey,count));
						chunkData = chunkData.subList(5, chunkData.size());
						realCount = Integer.parseInt(tmparray.get(maini).getCount(),16); 
						if(realCount>0) {
							for(int i=0;i<realCount;i++) {
								prefix = Utils.getHexFromUnsignedByteList(chunkData,0, hashLen);
								tmparray.get(maini).getPairs().add(i,new GSBPairs(prefix, chunkNum)); 
								chunkData = chunkData.subList(hashLen, chunkData.size());
							}
						}
						else if (realCount<0) {
							//Decoding Error, Somethings gone wrong!
						}
						maini++;
					}
					saveChunkPart( new GSBArray(chunkNum, hashLen, chunkLen, tmparray),GSBModeEnum.GSB_ADD,listname);
				}
				else if(type.equals("s")) {
					while(chunkData.size()>0) {
						hostKey = Utils.getHexFromUnsignedByteList(chunkData,0,4);
						count = Utils.getHexFromUnsignedByteList(chunkData,4);
						tmparray.add(new GSBTmpArray(hostKey,count));
						chunkData = chunkData.subList(5, chunkData.size());
						realCount = Integer.parseInt(tmparray.get(maini).getCount(),16);
						if(realCount>0) {
							for(int i=0;i<realCount;i++) {
								addChunkNum = Integer.parseInt(Utils.getHexFromUnsignedByteList(chunkData,0,4),16);
								prefix = Utils.getHexFromUnsignedByteList(chunkData,4, 4+(hashLen));
								tmparray.get(maini).getPairs().add(i,new GSBPairs(prefix, chunkNum));
								chunkData = chunkData.subList(4+(hashLen),chunkData.size());
							}
						}
						else if(realCount == 0) {
							addChunkNum = Integer.parseInt(Utils.getHexFromUnsignedByteList(chunkData,0,4),16);
							tmparray.get(maini).getPairs().add(0,new GSBPairs("", addChunkNum));
							chunkData = chunkData.subList(4,chunkData.size());
						}
						else{
							//Decoding Error, Somethings gone wrong!
						}
						maini++;
					}
					saveChunkPart(new GSBArray(chunkNum, hashLen, chunkLen, tmparray), GSBModeEnum.GSB_SUB, listname);
				}
				else {
					//"DISCARDED CHUNKNUM
				}
			}
			else {
				if(type.equals("a")) {
					saveChunkPart( new GSBArray(chunkNum, hashLen, chunkLen),GSBModeEnum.GSB_ADD,listname);
				}
				else if(type.equals("s")) {
					saveChunkPart(new GSBArray(chunkNum, hashLen, chunkLen), GSBModeEnum.GSB_SUB, listname);
				}
				else {
					//DISCARDED CHUNKNUM
				}
			}
			cloneData = splitHead.get(1).subList(chunkLen,splitHead.get(1).size());
		}
		return true;
	}

	/**
	 * Main part of updater function, will call all other functions, merely requires 
	 * the request body, it will then process and save all data as well as checking
	 * for ADD-DEL and SUB-DEL, runs silently so won't return anything on success
	 **/
	private boolean getData(String body){
		Map<String,List<String>> listFormatted;
		List<Integer> chunkData;
		String listName;
		String[] tabData;
		String[] valueSplitted;
		String[] tabSplit;
		List<String> listSplit;
		List<String> listData;
		int timeout = 0;
		Pattern p = Pattern.compile("n:(.*)");
		String result = "";
		String url = gsbUrl+"/downloads?client=api&apikey="+gsbKey+"&appver="+gsbAppVersion+"&pver="+gsbApiVersion;
		result = GSBURLUtil.googleDownloader(url, body, true);
		Matcher m = p.matcher(result);
		while(m.find()) {
			timeout = Integer.valueOf(m.group(1).replace("n:", "").trim());
		}
		setTimeout(timeout);
		if(GSBURLUtil.substr_count("r:pleasereset",result)>0) {
			resetDatabase();		
		}
		else {
			listFormatted = new HashMap<String,List<String>>();
			if(GSBURLUtil.substr_count("i:",result) > 0) {
				tabSplit = result.split("i:");
				listSplit = new ArrayList<String>(Arrays.asList(tabSplit));
				listSplit.remove(0);
				for(String splitted : listSplit) {
					tabData = splitted.split("\n");
					listData = new ArrayList<String>(Arrays.asList(tabData));
					listName = listData.get(0);
					listData.remove(0);
					listFormatted.put(listName, listData);
				}
				for (Iterator<String> it = listFormatted.keySet().iterator() ; it.hasNext() ; ){
					String key = (String) it.next();
					listData = (List<String>) listFormatted.get(key);
					listName = key;
					for(String valueInner : listData) {
						if(GSBURLUtil.substr_count("u:", valueInner) > 0) {
							chunkData = GSBURLUtil.googleDownloaderBytes("http://"+valueInner.replace("u:","").trim(), "data");	
							processChunks(chunkData, listName);
						}
						else if(GSBURLUtil.substr_count("ad:", valueInner)>0) {
							if(GSBURLUtil.substr_count(",", valueInner)>0) {
								valueSplitted = valueInner.replace("ad:", "").trim().split(",");
								for(int i=0;i<valueSplitted.length;i++) {
									deleteRange(valueSplitted[i],"add",listName);
								}
							}
							else {
								deleteRange(valueInner.replace("ad:", "").trim(),"add",listName);
							}
						}
						else if(GSBURLUtil.substr_count("sd:", valueInner)>0) {
							if(GSBURLUtil.substr_count(",", valueInner)>0) {
								valueSplitted = valueInner.replace("sd:", "").trim().split(",");
								for(int i=0;i<valueSplitted.length;i++) {
									deleteRange(valueSplitted[i],"sub",listName);
								}
							}
							else {
								deleteRange(valueInner.replace("sd:", "").trim(),"sub",listName);
							}
						}
					}
				}
			}
			else {
				//No data available in list
			}
		}
		return true;
	}

	/**
	 * Called when GSB returns a SUB-DEL or ADD-DEL response
	 * */
	private void deleteRange(String range, String mode, String listName) {
		Statement stmt;
		ResultSet rs;
		String sqlQuery;
		String buildTrunk;
		String clause;
		StringBuilder mergePrefixDel = new StringBuilder();
		String[] deleteRange;
		List<String> buildPrefixDel;
		Integer count=0;
		buildPrefixDel = new ArrayList<String>();
		buildTrunk = listName+"-"+mode;
		if(GSBURLUtil.substr_count("-",range)>0) {
			deleteRange = range.trim().split("-");
			clause = "`ChunkNum` >= "+deleteRange[0]+" AND `ChunkNum` <= "+deleteRange[1];
		}
		else {
			clause = "`ChunkNum` = '"+range+"'";
		}
		//Delete from index
		sqlQuery ="DELETE FROM `"+dbPrefix+buildTrunk+"-index` WHERE "+clause;
		try {
			stmt = con.createStatement();
			stmt.executeUpdate(sqlQuery);
			//Select all host keys that match chunks (we'll delete them after but we need the hostkeys list!)
			sqlQuery = "SELECT `Hostkey` FROM `"+dbPrefix+buildTrunk+"-hosts` WHERE "+clause;
			stmt = con.createStatement();
			rs = stmt.executeQuery(sqlQuery);
			while (rs.next()) {
				buildPrefixDel.add(rs.getString(0));
				count++;
				if(count == 100){
					mergePrefixDel.append(GSBURLUtil.implode(buildPrefixDel.toArray(), "' OR `Hostkey` = '"));
					//Delete all matching hostkey prefixes
					sqlQuery ="DELETE FROM `"+dbPrefix+buildTrunk+"-prefixes` WHERE `Hostkey` = '"+mergePrefixDel+"'";
					stmt = con.createStatement();
					stmt.executeUpdate(sqlQuery);
					count = 0;
					buildPrefixDel = new ArrayList<String>();
				}

			}
			mergePrefixDel.append(GSBURLUtil.implode(buildPrefixDel.toArray(), "' OR `Hostkey` = '"));
			//Delete all matching hostkey prefixes
			sqlQuery ="DELETE FROM `"+dbPrefix+buildTrunk+"-prefixes` WHERE `Hostkey` = '"+mergePrefixDel+"'";
			stmt = con.createStatement();
			stmt.executeUpdate(sqlQuery);
			//Delete all matching hostkeys
			sqlQuery ="DELETE FROM `"+dbPrefix+buildTrunk+"-hosts` WHERE "+clause;
			stmt = con.createStatement();
			stmt.executeUpdate(sqlQuery);
			stmt.close();
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Truncate all your GSB's tables
	 */
	public void resetDatabase() {
		Statement stmt;
		String SQL_QUERY;
		for(GSBListEnum gsbEnum : getListGSB()){
			SQL_QUERY = "TRUNCATE TABLE `"+dbPrefix+gsbEnum.getName()+"-sub-index`";	
			try {
				stmt = con.createStatement();
				stmt.execute(SQL_QUERY);
				SQL_QUERY = "TRUNCATE TABLE `"+dbPrefix+gsbEnum.getName()+"-sub-hosts`";
				stmt = con.createStatement();
				stmt.execute(SQL_QUERY);
				SQL_QUERY = "TRUNCATE TABLE `"+dbPrefix+gsbEnum.getName()+"-sub-prefixes`";
				stmt = con.createStatement();
				stmt.execute(SQL_QUERY);
				SQL_QUERY = "TRUNCATE TABLE `"+dbPrefix+gsbEnum.getName()+"-add-index`";	
				stmt = con.createStatement();
				stmt.execute(SQL_QUERY);
				SQL_QUERY = "TRUNCATE TABLE `"+dbPrefix+gsbEnum.getName()+"-add-hosts`";	
				stmt = con.createStatement();
				stmt.execute(SQL_QUERY);
				SQL_QUERY = "TRUNCATE TABLE `"+dbPrefix+gsbEnum.getName()+"-add-prefixes`";	
				stmt = con.createStatement();
				stmt.execute(SQL_QUERY);
			} catch (SQLException e) {
				e.printStackTrace();
			}
		}
	}

	private void saveChunkPart(GSBArray value, GSBModeEnum type, String listName) {
		Statement stmt;
		int listNum;
		int nbResult = 0;
		String indexInsert;
		String hostInsert;
		String sqlQuery;
		String pairInsert;

		List<String> buildIndex =  new ArrayList<String>();
		List<String> buildHost =  new ArrayList<String>();
		List<String> buildPairs =  new ArrayList<String>();
		if(listName.equals(gsbPhishingList)) {
			listNum = 0;
		}
		else {
			listNum = 1;
		}
		//Check what type of data it is...
		if(type.getId() == GSBModeEnum.GSB_SUB.getId()) {
			if(!mainList.get(GSBModeEnum.GSB_SUB.getId()).get(listNum).containsKey(value.getChunkNum())) {
				mainList.get(GSBModeEnum.GSB_SUB.getId()).get(listNum).put(value.getChunkNum(),true);
				buildIndex.add("('"+value.getChunkNum()+"','"+value.getChunkLen()+"')");
				if(value.getChunkLen()>0) {
					for(GSBTmpArray newValue : value.getReal()) {
						buildHost.add("('"+newValue.getHostKey()+"','"+value.getChunkNum()+"','"+newValue.getCount()+"')");
						if(newValue.getPairs() != null) {
							if(newValue.getPairs().size()>0) {
								for(GSBPairs innerValue : newValue.getPairs()) {
									if(innerValue.getPrefix() != null) {
										buildPairs.add("('"+newValue.getHostKey()+"','"+innerValue.getAddChunkNum()+"','"+innerValue.getPrefix()+"')");
									}
									else {
										buildPairs.add("('"+newValue.getHostKey()+"','"+innerValue.getAddChunkNum()+"','')");
									}
								}
							}
						}
					}
				}
			}
		}
		else if(type.getId() == GSBModeEnum.GSB_ADD.getId()){
			if(!mainList.get(GSBModeEnum.GSB_ADD.getId()).get(listNum).containsKey(value.getChunkNum())) {
				mainList.get(GSBModeEnum.GSB_ADD.getId()).get(listNum).put(value.getChunkNum(),true);
				buildIndex.add("('"+value.getChunkNum()+"','"+value.getChunkLen()+"')");
				if(value.getChunkLen()>0) {
					for(GSBTmpArray newValue : value.getReal()) {
						buildHost.add("('"+newValue.getHostKey()+"','"+value.getChunkNum()+"','"+newValue.getCount()+"')");
						if(newValue.getPairs() != null) {
							if(newValue.getPairs().size()>0) {
								for(GSBPairs innerValue : newValue.getPairs()) {
									if(innerValue.getPrefix() != null) {
										buildPairs.add("('"+newValue.getHostKey()+"','"+innerValue.getPrefix()+"')");
									}
									else {
										buildPairs.add("('"+newValue.getHostKey()+"','')");
									}
								}
							}
						}
					}
				}
			}
		}
		if(buildIndex.size()>0) {
			//Insert index value
			indexInsert = GSBURLUtil.implode(buildIndex.toArray(), ", ");
			sqlQuery = "INSERT INTO `"+dbPrefix+listName+"-"+type.getName()+"-index` (`ChunkNum`,`Chunklen`) VALUES "+indexInsert+";";
			try {
				stmt = con.createStatement();
				nbResult = stmt.executeUpdate(sqlQuery);
			} catch (SQLException e) {
				e.printStackTrace();
			}
			if(nbResult > 0) {
				if(buildHost.size()>0) {
					//Insert hostkeys index
					hostInsert = GSBURLUtil.implode(buildHost.toArray(), ", ");
					sqlQuery = "INSERT INTO `"+dbPrefix+listName+"-"+type.getName()+"-hosts` (`Hostkey`, `Chunknum`, `Count`) VALUES "+hostInsert+";";
					try {
						stmt = con.createStatement();
						nbResult = stmt.executeUpdate(sqlQuery);
					} catch (SQLException e) {
						e.printStackTrace();
					}
				}
				if(buildPairs.size()>0) {
					pairInsert = GSBURLUtil.implode(buildPairs.toArray(), ", ");
					if(type.getId() == GSBModeEnum.GSB_ADD.getId()) {
						sqlQuery = "INSERT INTO `"+dbPrefix+listName+"-"+type.getName()+"-prefixes` (`Hostkey`, `Prefix`) VALUES "+pairInsert+";";
					}
					else if(type.getId() == GSBModeEnum.GSB_SUB.getId()) {
						sqlQuery = "INSERT INTO `"+dbPrefix+listName+"-"+type.getName()+"-prefixes` (`Hostkey`, `AddChunkNum`, `Prefix`) VALUES "+pairInsert+";";
					}
					try{
						stmt = con.createStatement();
						nbResult = stmt.executeUpdate(sqlQuery);
					}
					catch (SQLException e) {
						e.printStackTrace();
					}
				}
			}
			else {
				//COULD NOT SAVE
			}
		}
	}

	/**
	 * Writes timeout from valid requests to nextcheck file
	 * */
	private void setTimeout(int seconds){
		PrintWriter out;
		String until;
		try {
			String sCurstatus = readFileAsString(pingFilePath+"nextcheck.dat").split("\\|\\|")[0];
			int curstatus = Integer.valueOf(sCurstatus);		
			until = System.currentTimeMillis()/1000+seconds+"||"+curstatus;
			out  = new PrintWriter(new FileWriter(pingFilePath+"nextcheck.dat"));
			out.println(until);
			out.close();
		}
		catch(Exception e){
			e.printStackTrace();
		}
	}

	/**
	 * Enum the GSB's list
	 */
	private void createGSBList() {
		listGSB = new ArrayList<GSBListEnum>();
		listGSB.add(GSBListEnum.GSB_MALWARE);
		listGSB.add(GSBListEnum.GSB_PHISHING);
	}

	private List<GSBListEnum> getListGSB() {
		return listGSB;
	}

	/**
	 * Generate the default database needed
	 */
	private void generateDatabase() {
		List<String> queries = new ArrayList<String>();
		queries.add("CREATE TABLE IF NOT EXISTS `"+dbPrefix+"goog-malware-shavar-add-hosts` (\n"+
				"`Hostkey` varchar(11) NOT NULL,\n"+
				"`ChunkNum` int(11) NOT NULL,\n"+
				"`Count` varchar(11) NOT NULL,\n"+
				"`FullHash` varchar(11) DEFAULT NULL,\n"+
				"INDEX `Hostkey` (`Hostkey` ASC)\n"+
				") ENGINE=MyISAM DEFAULT CHARSET=latin1;\n");

		queries.add("CREATE TABLE IF NOT EXISTS `"+dbPrefix+"goog-malware-shavar-add-index` ("+
				"`ChunkNum` int(11) NOT NULL,\n"+
				"`Chunklen` int(11) NOT NULL,\n"+
				"INDEX `ChunkNum` (`ChunkNum` ASC)\n"+
				") ENGINE=MyISAM DEFAULT CHARSET=latin1;\n");

		queries.add("CREATE TABLE IF NOT EXISTS `"+dbPrefix+"goog-malware-shavar-add-prefixes` (\n"+
				"`Hostkey` varchar(11) NOT NULL,\n"+
				"`Prefix` varchar(11) NOT NULL,\n"+
				"`FullHash` varchar(11) DEFAULT NULL,\n"+
				"INDEX `Hostkey` (`Hostkey` ASC)\n"+
				") ENGINE=MyISAM DEFAULT CHARSET=latin1;\n");

		queries.add("CREATE TABLE IF NOT EXISTS `"+dbPrefix+"goog-malware-shavar-sub-hosts` (\n"+
				"`Hostkey` varchar(11) NOT NULL,\n"+
				"`Chunknum` int(11) NOT NULL,\n"+
				"`Count` varchar(11) NOT NULL,\n"+
				"`FullHash` varchar(11) DEFAULT NULL,\n"+
				"INDEX `Hostkey` (`Hostkey` ASC)\n"+
				") ENGINE=MyISAM DEFAULT CHARSET=latin1;\n");

		queries.add("CREATE TABLE IF NOT EXISTS `"+dbPrefix+"goog-malware-shavar-sub-index` (\n"+
				"`ChunkNum` int(11) NOT NULL,\n"+
				"`Chunklen` int(11) NOT NULL,\n"+
				"INDEX `ChunkNum` (`ChunkNum` ASC)\n"+
				") ENGINE=MyISAM DEFAULT CHARSET=latin1;\n");

		queries.add("CREATE TABLE IF NOT EXISTS `"+dbPrefix+"goog-malware-shavar-sub-prefixes` (\n"+
				"`Hostkey` varchar(11) NOT NULL,\n"+
				"`AddChunkNum` int(11) NOT NULL,\n"+
				"`Prefix` varchar(11) NOT NULL,\n"+
				"`FullHash` varchar(11) DEFAULT NULL,\n"+
				"INDEX `Hostkey` (`Hostkey` ASC)\n"+
				") ENGINE=MyISAM DEFAULT CHARSET=latin1;\n");

		queries.add("CREATE TABLE IF NOT EXISTS `"+dbPrefix+"googpub-phish-shavar-add-hosts` (\n"+
				"`Hostkey` varchar(11) NOT NULL,\n"+
				"`ChunkNum` int(11) NOT NULL,\n"+
				"`Count` varchar(11) NOT NULL,\n"+
				"`FullHash` varchar(11) DEFAULT NULL,\n"+
				"INDEX `Hostkey` (`Hostkey` ASC)\n"+
				") ENGINE=MyISAM DEFAULT CHARSET=latin1;\n");

		queries.add("CREATE TABLE IF NOT EXISTS `"+dbPrefix+"googpub-phish-shavar-add-index` (\n"+
				"`ChunkNum` int(11) NOT NULL,\n"+
				"`Chunklen` int(11) NOT NULL,\n"+
				"INDEX `ChunkNum` (`ChunkNum` ASC)\n"+
				") ENGINE=MyISAM DEFAULT CHARSET=latin1;\n");

		queries.add("CREATE TABLE IF NOT EXISTS `"+dbPrefix+"googpub-phish-shavar-add-prefixes` (\n"+
				"`Hostkey` varchar(11) NOT NULL,\n"+
				"`Prefix` varchar(11) NOT NULL,\n"+
				"`FullHash` varchar(11) DEFAULT NULL,\n"+
				"INDEX `Hostkey` (`Hostkey` ASC)\n"+
				") ENGINE=MyISAM DEFAULT CHARSET=latin1;\n");

		queries.add("CREATE TABLE IF NOT EXISTS `"+dbPrefix+"googpub-phish-shavar-sub-hosts` (\n"+
				"`Hostkey` varchar(11) NOT NULL,\n"+
				"`ChunkNum` int(11) NOT NULL,\n"+
				"`Count` varchar(11) NOT NULL,\n"+
				"`FullHash` varchar(11) DEFAULT NULL,\n"+
				"INDEX `Hostkey` (`Hostkey` ASC)\n"+
				") ENGINE=MyISAM DEFAULT CHARSET=latin1;\n");

		queries.add("CREATE TABLE IF NOT EXISTS `"+dbPrefix+"googpub-phish-shavar-sub-index` (\n"+
				"`ChunkNum` int(11) NOT NULL,\n"+
				"`ChunkLen` int(11) NOT NULL,\n"+
				"INDEX `ChunkNum` (`ChunkNum` ASC)\n"+
				") ENGINE=MyISAM DEFAULT CHARSET=latin1;\n");

		queries.add("CREATE TABLE IF NOT EXISTS `"+dbPrefix+"googpub-phish-shavar-sub-prefixes` (\n"+
				"`Hostkey` varchar(11) NOT NULL,\n"+
				"`AddChunkNum` varchar(11) NOT NULL,\n"+
				"`Prefix` varchar(11) NOT NULL,\n"+
				"`Fullhash` varchar(11) DEFAULT NULL,\n"+
				"INDEX `Hostkey` (`Hostkey` ASC)\n"+
				") ENGINE=MyISAM DEFAULT CHARSET=latin1;\n");
		try {
			Statement stmt = con.createStatement();
			for(String query : queries){
				stmt.execute(query);
			}			
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}
	
	/** 
	 * Read a file and return a string
	 * @param filePath the name of the file to open. Not sure if it can accept URLs or just filenames. Path handling could be better, and buffer sizes are hardcoded
	 * @return content of the file
	 */ 
	private String readFileAsString(String filePath) throws java.io.IOException{
		StringBuffer fileData = new StringBuffer(1000);
		BufferedReader reader = new BufferedReader(new FileReader(getPath()+filePath));
		char[] buf = new char[1024];
		int numRead=0;
		while((numRead=reader.read(buf)) != -1){
			String readData = String.valueOf(buf, 0, numRead);
			fileData.append(readData);
			buf = new char[1024];
		}
		reader.close();
		//If the file is empty, we set a default value
		if(fileData.length() < 1) {
			fileData = fileData.append("0||");
		}
		return fileData.toString();
	}

	private String getPath() {
		return path;
	}
}