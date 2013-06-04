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
 * Fill a database with GSB\'s datas
 * @author Julien Sosin <jsosin@domaintools.com>
 * 
 * Modified by Liming Hu liming.hu@globalsign.com
 * To make it work with PostgreSQL database.
 * 
 */
public class GSBCrawler {

	//GSB
	private static List<GSBListEnum> listGSB;
	private String gsbUrl = "http://safebrowsing.clients.google.com/safebrowsing";
	private String gsbKey = "";
	//googpub-phish-shavar
	//goog-malware-shavar
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
	 * Create a Wrapper to use Google Safe Browsing.
	 * This wrapper allows to use your GSB\'s database to looking for some malware/phishing website
	 * @param gsbKey : The key provided by GSB
	 * @param dbPrefix : Prefix you will use in YOUR database
	 * @param path : Path where the wrapper will create files
	 * @param dbUrl : The database url use by jdbc Example : jdbc:mysql://localhost/gsb
	 * @param dbUsername : The database\'s username
	 * @param dbPassword : The database\'s password
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
			Class.forName("org.postgresql.Driver");
		} catch (SQLException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
		//we will using psql to create the databases.
		//generateDatabase();
	}

	/**
	 * Update the GSB\'s database
	 * @return the number of seconds to wait before the next request
	 */
	public Integer updateDB() {
		Integer res = -1;
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
	 * Create files needed to stock some data
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
			System.out.println(body.toString());
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
		//googpub-phish-shavar add index
		//goog-malware-shavar
		String checktable = gsbList.getName()+"_"+mode.getName()+"_index";
		System.out.println(checktable);
		String SQL_QUERY ="SELECT ChunkNum FROM "+dbPrefix+"\""+checktable+"\""+" ORDER BY ChunkNum ASC";
		Statement stmt;
		try {
			stmt = con.createStatement();
			System.out.println(SQL_QUERY);
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
	 * Processes data received from a GSB data request into a manageable array
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
							System.out.println("Decoding Error, Somethings gone wrong!");
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
							System.out.println("Decoding Error, Somethings gone wrong!");
						}
						maini++;
					}
					saveChunkPart(new GSBArray(chunkNum, hashLen, chunkLen, tmparray), GSBModeEnum.GSB_SUB, listname);
				}
				else {
					//"DISCARDED CHUNKNUM"
					System.out.println("DISCARDED CHUNKNUM!");
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
					System.out.println("DISCARDED CHUNKNUM!");
				}
			}
			cloneData = splitHead.get(1).subList(chunkLen,splitHead.get(1).size());
		}
		return true;
	}

	/**
	 * Main part of updater function, will call all other functions, merely requires 
	 * the request body, it will then process and save all data as well as checking
	 * for ADD-DEL and SUB-DEL, runs silently so won\'t return anything on success
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
		
		//http://safebrowsing.clients.google.com/safebrowsing/downloads?client=api&apikey=ABQIAAAAJITJMgA23cKFczNFmGOKfhQVNDY5dS3MozaSszWw6_ovAoZkwQ&appver=1.5.2&pver=2.2
		//	goog_malware_shavar;
		//	googpub_phish_shavar;
		
		//googpub-phish-shavar
		//goog-malware-shavar

		System.out.println(url);
		System.out.println(body);
		
		/*
		 * corresponding chunk type. Example (inline comments start after a # and are not part of the protocol:)

googpub-phish-shavar;a:1-5      # The client has 'add' chunks but no 'sub' chunks

acme-malware-shavar;           # The client has no data for this list.

acme-white-shavar;mac        # No data here either and it wants a mac
Examples of good chunk lists:

googpub-phish-shavar;a:1-5,10,12:s:3-8
googpub-phish-shavar;a:1,2,3,4,5,10,12,15,16
googpub-phish-shavar;a:1-5,10,12,15-16
googpub-phish-shavar;a:16-10,2-5,4
Examples of bad chunk lists:

googpub-phish-shavar              # Missing ; at end of list name
googpub-phish-shavar;5-1,16-10    # Missing 'a:' or 's:' for chunk type
googpub-phish-shavar;a:5-1:s:     # Missing chunk numbers for 's:'
Server Behavior:

The server MUST reject a request with an empty body.
The server MUST ignore ill-formated lines and MUST reply to the correctly formatted ones.
The server SHALL try to accommodate the desired response size. The requested size takes into account only chunk data, not any metadata.
However if the desired size is less than at least one chunk, the server MUST send at least one chunk.

		 * 
		 */
		
		//goog-malware-shavar;s:110561_111407:a:111201_112180
		//googpub-phish-shavar;s:9761_10107:a:232961_236375
		
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
				System.out.println("No data available in list!");
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
		buildTrunk = listName+"_"+mode;
		if(GSBURLUtil.substr_count("-",range)>0) {
			deleteRange = range.trim().split("-");
			clause = "ChunkNum >= "+deleteRange[0]+" AND ChunkNum <= "+deleteRange[1];
		}
		else {
			clause = "ChunkNum = "+range+"";
		}
		//Delete from index
		sqlQuery ="DELETE FROM "+"\""+dbPrefix+buildTrunk+"_index"+"\""+" WHERE "+clause;
		try {
			stmt = con.createStatement();
			System.out.println(sqlQuery);
			//
			//DELETE FROM googpub-phish-shavar_add_index WHERE ChunkNum >= 223914 AND ChunkNum <= 224188
			//		org.postgresql.util.PSQLException: ERROR: syntax error at or near "-"
			//  Position: 20
			stmt.executeUpdate(sqlQuery);
			//Select all host keys that match chunks (we\'ll delete them after but we need the hostkeys list!)
			sqlQuery = "SELECT Hostkey FROM "+dbPrefix+"\""+buildTrunk+"_hosts"+ "\""+" WHERE "+clause;
			stmt = con.createStatement();
			System.out.println(sqlQuery);
			rs = stmt.executeQuery(sqlQuery);
			while (rs.next()) {
				buildPrefixDel.add(rs.getString(1));
				count++;
				if(count == 100){
					mergePrefixDel.append(GSBURLUtil.implode(buildPrefixDel.toArray(), " OR Hostkey = "));
					//Delete all matching hostkey prefixes
					sqlQuery ="DELETE FROM "+dbPrefix+"\""+buildTrunk+"_prefixes"+"\""+" WHERE Hostkey = "+"\'"+ mergePrefixDel+"\'"+"";
					stmt = con.createStatement();
					System.out.println(sqlQuery);
					stmt.executeUpdate(sqlQuery);
					count = 0;
					buildPrefixDel = new ArrayList<String>();
				}

			}
			mergePrefixDel.append(GSBURLUtil.implode(buildPrefixDel.toArray(), " OR Hostkey = "));
			//Delete all matching hostkey prefixes
			sqlQuery ="DELETE FROM "+dbPrefix+"\""+buildTrunk+"_prefixes"+"\""+" WHERE Hostkey = "+"\'"+mergePrefixDel+"\'"+"";
			stmt = con.createStatement();
			//DELETE FROM "googpub-phish-shavar_add_index" WHERE ChunkNum >= 223914 AND ChunkNum <= 224188
			//SELECT Hostkey FROM "googpub-phish-shavar_add_hosts" WHERE ChunkNum >= 223914 AND ChunkNum <= 224188
			//		org.postgresql.util.PSQLException: ERROR: syntax error at or near "a609ec5"
			//		  Position: 66
			stmt.executeUpdate(sqlQuery);
			//Delete all matching hostkeys
			sqlQuery ="DELETE FROM "+dbPrefix+"\""+buildTrunk+"_hosts"+"\""+" WHERE "+clause;
			stmt = con.createStatement();
			System.out.println(sqlQuery);
			stmt.executeUpdate(sqlQuery);
			stmt.close();
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Truncate all your GSB\'s tables
	 */
	public void resetDatabase() {
		Statement stmt;
		String SQL_QUERY;
		for(GSBListEnum gsbEnum : getListGSB()){
			SQL_QUERY = "TRUNCATE TABLE "+dbPrefix+"\""+gsbEnum.getName()+"_sub_index"+"\"";	
			try {
				stmt = con.createStatement();
				stmt.execute(SQL_QUERY);
				SQL_QUERY = "TRUNCATE TABLE "+dbPrefix+"\""+gsbEnum.getName()+"_sub_hosts_"+"\"";
				stmt = con.createStatement();
				stmt.execute(SQL_QUERY);
				SQL_QUERY = "TRUNCATE TABLE "+dbPrefix+"\""+gsbEnum.getName()+"_sub_prefixes"+"\"";
				stmt = con.createStatement();
				stmt.execute(SQL_QUERY);
				SQL_QUERY = "TRUNCATE TABLE "+dbPrefix+"\""+gsbEnum.getName()+"_add_index"+"\"";	
				stmt = con.createStatement();
				stmt.execute(SQL_QUERY);
				SQL_QUERY = "TRUNCATE TABLE "+dbPrefix+"\""+gsbEnum.getName()+"_add_hosts"+"\"";	
				stmt = con.createStatement();
				stmt.execute(SQL_QUERY);
				SQL_QUERY = "TRUNCATE TABLE "+dbPrefix+"\""+gsbEnum.getName()+"_add_prefixes"+"\"";	
				stmt = con.createStatement();
				System.out.println(SQL_QUERY);
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
				buildIndex.add("("+value.getChunkNum()+","+value.getChunkLen()+")");
				if(value.getChunkLen()>0) {
					for(GSBTmpArray newValue : value.getReal()) {
						buildHost.add("("+"\'"+newValue.getHostKey()+"\'"+","+value.getChunkNum()+","+"\'"+newValue.getCount()+"\'"+")");
						if(newValue.getPairs() != null) {
							if(newValue.getPairs().size()>0) {
								for(GSBPairs innerValue : newValue.getPairs()) {
									if(innerValue.getPrefix() != null) {
										buildPairs.add("("+"\'"+newValue.getHostKey()+"\'"+","+innerValue.getAddChunkNum()+","+"\'"+innerValue.getPrefix()+"\'"+")");
									}
									else {
										buildPairs.add("("+"\'"+newValue.getHostKey()+"\'"+","+innerValue.getAddChunkNum()+",)");
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
				buildIndex.add("("+value.getChunkNum()+","+value.getChunkLen()+")");
				if(value.getChunkLen()>0) {
					for(GSBTmpArray newValue : value.getReal()) {
						buildHost.add("("+"\'"+newValue.getHostKey()+"\'"+","+value.getChunkNum()+","+"\'"+newValue.getCount()+"\'"+")");
						if(newValue.getPairs() != null) {
							if(newValue.getPairs().size()>0) {
								for(GSBPairs innerValue : newValue.getPairs()) {
									if(innerValue.getPrefix() != null) {
										buildPairs.add("("+"\'"+newValue.getHostKey()+"\'"+","+"\'"+innerValue.getPrefix()+"\'"+")");
									}
									else {
										buildPairs.add("("+"\'"+newValue.getHostKey()+"\'"+",)");
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
			//INSERT INTO "googpub-phish-shavar_add_index" (ChunkNum,Chunklen) VALUES "(233258,344)";
			//org.postgresql.util.PSQLException: ERROR: syntax error at or near ""(233258,344)""
			//  Position: 73
			sqlQuery = "INSERT INTO "+dbPrefix+"\""+listName+"_"+type.getName()+"_index"+"\""+" (ChunkNum,Chunklen) VALUES "+indexInsert+";";
			try {
				stmt = con.createStatement();
				System.out.println(sqlQuery);
				//INSERT INTO "googpub-phish-shavar_sub_index" (ChunkNum,Chunklen) VALUES (10049,9);
				nbResult = stmt.executeUpdate(sqlQuery);
			} catch (SQLException e) {
				e.printStackTrace();
			}
			if(nbResult > 0) {
				if(buildHost.size()>0) {
					//Insert hostkeys index
					hostInsert = GSBURLUtil.implode(buildHost.toArray(), ", ");
					sqlQuery = "INSERT INTO "+dbPrefix+"\""+listName+"_"+type.getName()+"_hosts"+"\""+" (Hostkey, Chunknum, Count) VALUES "+hostInsert+";";
					try {
						stmt = con.createStatement();
						System.out.println(sqlQuery);
						//INSERT INTO "goog-malware-shavar_sub_hosts" (Hostkey, Chunknum, Count) VALUES ('bc3eb373',110650,d), ('92bbb445',110650,0), ('beb529b4',110650,0), ('964fed92',110650,0), ('c6ddd7d',110650,1), ('e73ee4b',110650,1), ('864f644',110650,1), ('3218a5dd',110650,0), ('c77a7ce3',110650,0), ('9553dac9',110650,0), ('c4a71867',110650,0), ('45f794b7',110650,0), ('c885af95',110650,0), ('f6f6fb4',110650,0), ('f8b6c2f7',110650,0), ('b6418fe3',110650,0), ('cf59ba11',110650,0), ('8e9b9f9c',110650,0), ('d62e2661',110650,0), ('fce1590',110650,0), ('a53b572',110650,0), ('ed3712f2',110650,1), ('4349d32c',110650,1), ('9f4e9437',110650,0), ('522057d7',110650,0), ('a04d604f',110650,0), ('9852e7c',110650,0), ('845b5472',110650,0), ('532ba2d0',110650,0), ('a697365a',110650,0), ('366fcf53',110650,0), ('8054548b',110650,0), ('81708bb',110650,0), ('e09a5f67',110650,0), ('eb8aa18e',110650,1), ('55d1c619',110650,1), ('a1392c18',110650,0), ('cfde69d',110650,0), ('b18b571c',110650,4), ('59c61fe9',110650,0), ('de8e33ab',110650,0), ('4e97a68',110650,0), ('509249a8',110650,0), ('bb74c027',110650,0), ('70ddfb6c',110650,1), ('cf175393',110650,0), ('f699f2f3',110650,0), ('8c8c18fa',110650,0), ('927a4bc2',110650,0), ('8f9343f8',110650,0), ('e526560',110650,0), ('54fdab6',110650,0), ('3844758a',110650,0), ('7d5a4299',110650,0), ('b4dfb329',110650,1), ('d6cabb22',110650,0), ('1fed31cf',110650,2), ('5ded785b',110650,0), ('875b929',110650,0), ('ba34281',110650,1), ('cc67dc9f',110650,0), ('c6fd6493',110650,0), ('918ae4a',110650,0), ('d5aca5a5',110650,0), ('9da9be74',110650,0), ('751a88c5',110650,2), ('bee6e8bb',110650,1), ('aa7c21c1',110650,0), ('6e86fa7e',110650,0), ('3c85e3bc',110650,1), ('9affce8d',110650,2), ('17d7755a',110650,0), ('579480bd',110650,0), ('10b5c60',110650,0), ('782b263',110650,0), ('20a90b7',110650,0), ('4588e5a4',110650,0), ('24801a61',110650,1), ('91155cf8',110650,0), ('597d52a',110650,0), ('926c73ad',110650,0), ('2c702228',110650,0), ('217952b',110650,1), ('397be173',110650,1), ('531a9b8',110650,1), ('634fb56',110650,1), ('a8251e36',110650,0), ('617c5ce9',110650,0), ('61f5c7d',110650,0), ('b1216231',110650,0), ('45d6668',110650,0), ('d4c11314',110650,0), ('81ad4d16',110650,7), ('dfc5514',110650,0), ('5cca60fc',110650,0), ('d240da7f',110650,0), ('248b51cc',110650,0), ('163d3f9a',110650,0), ('35a17ef0',110650,0), ('4f94f7d4',110650,0), ('e26a49',110650,0), ('7525e16',110650,0), ('11c66ebb',110650,0), ('50579f45',110650,1), ('a4b6deee',110650,0), ('3fc19b6b',110650,0), ('a5e07a14',110650,0), ('84f61229',110650,0), ('eeb21b6',110650,0), ('905d4baa',110650,2), ('64dd865e',110650,1), ('83c6f6e4',110650,0), ('4b6ed975',110650,0), ('6ce8369a',110650,1), ('7a2ca6cc',110650,0), ('c4e033a4',110650,0), ('9265a2d7',110650,0), ('bd2f7774',110650,0), ('5eb028fe',110650,0), ('e386817',110650,0), ('b1a2b476',110650,0), ('ae61e21d',110650,0), ('385bef9',110650,0), ('8e2ca720',110650,2), ('316138e',110650,0), ('4c9173b',110650,0), ('4887eb62',110650,0), ('3eadcd3c',110650,1), ('5570c864',110650,1), ('d141926a',110650,1), ('799a353',110650,0), ('d31c337a',110650,0), ('3df1b965',110650,1), ('14c91337',110650,0), ('9049b4c4',110650,1), ('b73efa25',110650,0), ('50468d13',110650,0), ('afa07ec6',110650,1), ('97e99e12',110650,0), ('69e04cb',110650,0), ('b8998c13',110650,0), ('58ab1628',110650,0), ('3d28143',110650,0), ('849b2435',110650,0), ('a4204ef1',110650,0), ('77b4cd1d',110650,0), ('2166fdb5',110650,0), ('8e1b7979',110650,0), ('55f43ca2',110650,0), ('87f37fae',110650,0), ('3e6bb029',110650,0), ('60ab9c45',110650,0), ('9eb682c7',110650,1), ('10206692',110650,0), ('1627ce38',110650,0), ('116c5293',110650,0), ('5f8ddc23',110650,0), ('7a9cae2a',110650,0), ('30189fb7',110650,0), ('d9f83a4',110650,0), ('f77a3fa6',110650,1), ('12592273',110650,1), ('f1cb8f2d',110650,1), ('a0f9a9ac',110650,1), ('1714d4e5',110650,0), ('4a4f6f9',110650,0), ('dd0ad56',110650,0), ('ca7d2510',110650,0), ('e0ec8ba',110650,0), ('a4fcbab8',110650,0), ('11545e6',110650,0), ('54dad28f',110650,0), ('9397074',110650,0), ('b3bff23b',110650,0), ('e391dcdf',110650,1), ('8ecee885',110650,0), ('bca7c9f',110650,0), ('31dd20aa',110650,0), ('722c99a0',110650,0), ('27a8218d',110650,0), ('586ed7c0',110650,0), ('e069bf3',110650,0), ('1a1696d',110650,1), ('dd5f7dc5',110650,1), ('98f0394',110650,0), ('515921ca',110650,0), ('c223548e',110650,0), ('5e91ff62',110650,0), ('6d131533',110650,0), ('c57e7aaf',110650,0), ('7be62cc',110650,1), ('ed85d86c',110650,0), ('c89f84c9',110650,0), ('5ba0c822',110650,0), ('d75e41ec',110650,0), ('94674aa9',110650,0), ('bfa3206d',110650,0), ('614fab5',110650,0), ('f78c4283',110650,0), ('f4baf736',110650,1), ('96c258ba',110650,0), ('25d4f1d',110650,0), ('21e7e31c',110650,1), ('157bfb22',110650,0), ('c8a636eb',110650,0), ('63816771',110650,0), ('97e3e216',110650,0), ('b8c972d',110650,0), ('2ec5e4e7',110650,0), ('37e78da1',110650,0), ('5d04c8b',110650,0), ('14d8bfc',110650,0), ('ae434bdd',110650,0), ('2aa7ab64',110650,4), ('719783a0',110650,0), ('9a4d680',110650,2), ('c447b4f1',110650,0), ('151fa15',110650,1), ('624b1fb',110650,0), ('c02756bc',110650,0), ('5542e77a',110650,0), ('42cb298',110650,0), ('ae9e80df',110650,0), ('cf823d4',110650,0), ('2b76553',110650,0), ('4beb889',110650,0), ('233e5a3d',110650,0), ('1cb8d474',110650,1), ('8c79f0ce',110650,0), ('6035a6ad',110650,0), ('3f6e4b62',110650,0), ('f74e4f3f',110650,1), ('b260a5f2',110650,0), ('7cb9b42',110650,0), ('bc4a2d19',110650,0), ('8083890',110650,1), ('f9354116',110650,0), ('fa6a5096',110650,0), ('ff14e572',110650,1), ('c9c07c6d',110650,0), ('786b3de3',110650,0), ('cd5f1dfe',110650,0), ('52d5b0ff',110650,1), ('4ba0102f',110650,1), ('bc29c06a',110650,0), ('cef8e8f2',110650,0), ('a1cb32b',110650,1), ('7e799a71',110650,0), ('7fcf1bc',110650,0), ('711a420',110650,0), ('d0d82a7',110650,1), ('db50b59e',110650,0), ('836f78',110650,1), ('4adcb25',110650,0), ('978144b4',110650,0), ('93e32c2b',110650,0), ('bad74f27',110650,0), ('4fb896e7',110650,1), ('553679c1',110650,0), ('2319af3a',110650,0), ('924af88',110650,1), ('d76abd2',110650,0), ('3d5db459',110650,0), ('f8bb8f71',110650,0), ('7e7a37cb',110650,1), ('a9656dc0',110650,0), ('d5baba34',110650,0), ('ec2f9d9',110650,0), ('cfc77355',110650,0), ('42ca888',110650,0), ('2669465b',110650,0), ('34461b1f',110650,0), ('75e97cf',110650,0), ('a14db26b',110650,0), ('a530e245',110650,0), ('524c3c79',110650,0), ('2f3929ef',110650,0), ('622def5',110650,1), ('c9657b18',110650,0), ('e392b7fb',110650,0), ('651acf1',110650,0), ('a04e2fc4',110650,0), ('4addc9',110650,2), ('d0f25bd',110650,0), ('54758268',110650,0), ('4c7c42c',110650,0), ('acc0e466',110650,1), ('b8bfb2b8',110650,1), ('98ca2f24',110650,3), ('d6d4c64f',110650,0), ('9a63f1e3',110650,0), ('a3ec8afe',110650,0), ('d02c5356',110650,0), ('aca9a4e3',110650,1), ('67129c8b',110650,0), ('8d2fa56d',110650,0), ('438dcd80',110650,0), ('42bdd3fe',110650,1), ('a7ba34ea',110650,3), ('14427745',110650,0), ('7952a897',110650,0), ('e2ed096',110650,0), ('36f02078',110650,0), ('f885a2e1',110650,0), ('1cfcfe9a',110650,0), ('db56a8a',110650,0), ('c62cfc57',110650,0), ('13887a',110650,1), ('bfc8456f',110650,0), ('ae334ae7',110650,0), ('a1d379a6',110650,0), ('58f5127e',110650,0), ('a0c7bb1',110650,0), ('cc5d39d',110650,0), ('80eac3df',110650,0), ('851d56',110650,0), ('d940b584',110650,0), ('c9802b95',110650,0), ('ac6b1cb',110650,0), ('a49be22c',110650,0), ('2d6ba169',110650,0), ('7acf7a5',110650,0), ('20fc1af9',110650,0), ('75c22c59',110650,0), ('57a3a6b',110650,0), ('5699139',110650,1), ('ab892bfe',110650,0), ('542f60da',110650,0), ('6d4b26d8',110650,0), ('df884c5',110650,0), ('a342997b',110650,0), ('ec7a47c5',110650,0), ('88109e38',110650,0), ('ecbe465b',110650,2), ('4879fe69',110650,0), ('b3bb940',110650,1), ('f2b73c0',110650,0), ('ee8eae9e',110650,0), ('4d82edea',110650,0), ('d2d318a',110650,0), ('a5c0113b',110650,0), ('77633683',110650,1), ('487f2245',110650,0), ('d4d433f6',110650,0), ('f0b73970',110650,3), ('c6e164e4',110650,0), ('8a54217b',110650,0), ('92e013fe',110650,0), ('b6e1a436',110650,0), ('e5265fb',110650,0), ('e9c6a83c',110650,0), ('5b7dca3b',110650,0), ('d1eccaa5',110650,0), ('34818f8c',110650,0), ('fa4aae4',110650,0), ('7b977b66',110650,0), ('9178e56d',110650,0), ('211fe2d4',110650,0), ('59d647d1',110650,0), ('fd1811c',110650,0), ('baa234c6',110650,0), ('ac6eeb7',110650,0), ('80b0c5ee',110650,0), ('96f58fd',110650,0), ('5ba8f98',110650,0), ('2ed8730',110650,0), ('b8c75759',110650,0), ('f1727a2c',110650,0), ('47da4e6',110650,0), ('1b82c91',110650,0), ('4a9df348',110650,0), ('4475be87',110650,0), ('7b6dc569',110650,0), ('19e047cd',110650,0), ('77a9e85b',110650,0), ('a93742f',110650,0), ('c991742f',110650,0), ('1a59bc',110650,1), ('ed4d623',110650,0), ('f26178',110650,0), ('4f2a84e7',110650,0), ('cb7dc124',110650,2), ('db367472',110650,1), ('e5476a94',110650,0), ('81c0998a',110650,0), ('fb10c453',110650,0), ('50535ded',110650,0), ('6ca59a9',110650,1), ('93eee69d',110650,0), ('fc4d415',110650,0), ('783f3ec3',110650,1), ('573cf3aa',110650,0), ('79c5f824',110650,1), ('1636a481',110650,0), ('bc7041d',110650,0), ('861a59e',110650,0), ('523d79af',110650,0), ('46ce613',110650,0), ('b3ec4442',110650,0), ('7655ad30',110650,1), ('a225e2c6',110650,0), ('70c05c96',110650,0), ('c019370',110650,1), ('5da6426',110650,0), ('af5eb8cf',110650,b), ('41f2af9d',110650,0), ('8eb135c6',110650,2), ('8e6eacaa',110650,1), ('7329125e',110650,0), ('5f8ccbbd',110650,0), ('c4ebd1b8',110650,0), ('dea4817',110650,1), ('47337fe6',110650,0), ('6653f982',110650,0), ('ae22cb5e',110650,0), ('8096336e',110650,0), ('b45af66',110650,0), ('b92c48ce',110650,1), ('c32f1596',110650,0), ('6b38e9c7',110650,0), ('9de949f9',110650,0), ('6eaf889',110650,0), ('e5d23ec',110650,0), ('d2ca15ed',110650,0), ('cbd437bb',110650,0), ('fe6ac040',110650,0), ('856a59a',110650,0), ('f55761d3',110650,0), ('8b8a4f4',110650,0), ('ae1c7fab',110650,0), ('56694765',110650,0), ('3c6c1c0',110650,0), ('a6d43d23',110650,1), ('b08f3d4e',110650,1), ('8560127c',110650,0), ('6148d3dc',110650,0), ('618e6775',110650,0), ('16c5fe77',110650,0), ('6aa8823f',110650,0), ('9265bb',110650,0), ('7d58a047',110650,0), ('5088cb80',110650,0), ('b62fd98',110650,0), ('8fdb62ba',110650,b), ('7a64c594',110650,0), ('b8cd812a',110650,0), ('b472ab24',110650,0), ('a5f05a5c',110650,0), ('44e0199',110650,1), ('9b272eda',110650,1), ('d341e3d',110650,0), ('866d6b6c',110650,0), ('c1c57238',110650,0), ('eab012a6',110650,0), ('ceca13e0',110650,0), ('f8babcd1',110650,2), ('aa7868ff',110650,0), ('339a1478',110650,0), ('86bc3954',110650,0), ('dece80dd',110650,0), ('9e9cb54c',110650,1), ('58885a6',110650,1), ('4ea8125',110650,0), ('7ff495b8',110650,0), ('4969681b',110650,0), ('38e8f191',110650,0), ('6e3454c',110650,d), ('88df8167',110650,0), ('5d331e37',110650,0), ('b77e8af1',110650,0), ('ee9b6b1b',110650,0), ('3b4b2d7e',110650,0), ('8f2edf54',110650,0), ('b7a6bf20',110650,0), ('4e3b8cf2',110650,1), ('e38abd1b',110650,0), ('a12b4642',110650,0), ('4bf5bdf',110650,0), ('5771b8dc',110650,1), ('80a31a7',110650,0), ('18101449',110650,0), ('2d0f3d0',110650,0), ('1bad60d1',110650,1), ('2552745e',110650,0), ('4cc73429',110650,0), ('16b9c9e8',110650,0), ('8e8a439',110650,0), ('df5f54f',110650,0), ('1471c63c',110650,0), ('a48cd315',110650,1), ('de171f47',110650,3), ('9f68c77d',110650,0), ('e911952e',110650,0), ('ab392bf7',110650,3), ('2817a3d1',110650,0), ('29ac1449',110650,0), ('7d5183e2',110650,0), ('f1cccda1',110650,0), ('1cc01f',110650,0), ('a56af455',110650,0), ('9d4eeea5',110650,1), ('b950bbc8',110650,0), ('39d3afd4',110650,0), ('4aea635c',110650,0), ('b720f0',110650,1), ('7014c334',110650,0), ('c865d2df',110650,0), ('597472',110650,0), ('8e7b2b47',110650,0), ('a90421a',110650,0), ('473fdfc',110650,0), ('aaf96feb',110650,0), ('79f96ca2',110650,0), ('928620',110650,1), ('be8d232c',110650,0), ('b645bc26',110650,0), ('74bea63b',110650,0), ('af85cb4a',110650,0), ('6e857db',110650,0), ('5b807acd',110650,0), ('d430add8',110650,0), ('6e6ca57d',110650,0), ('9bf04757',110650,0), ('6946155',110650,0), ('a35ac93',110650,0), ('ed4a1eac',110650,0), ('46b51577',110650,1), ('36638bb2',110650,0), ('38fdfce7',110650,0), ('d01c98d7',110650,0), ('a32a796',110650,0), ('b93a4b34',110650,1), ('229e8bef',110650,0), ('14b1cfdd',110650,0), ('e152432c',110650,1), ('e3f4e9c9',110650,1), ('2317abbd',110650,0), ('40427f64',110650,0), ('9f8e7d7',110650,1), ('5a054e8',110650,0), ('5acc193',110650,0), ('2ada5d89',110650,2), ('a0db72ec',110650,0), ('bb62a4b1',110650,0), ('c26c4ac8',110650,0), ('99b7f21d',110650,0), ('311f2eef',110650,0), ('199089d8',110650,0), ('a41d8c6',110650,0), ('d2622735',110650,0), ('b432d8b4',110650,1), ('10d36059',110650,0), ('3395538a',110650,0), ('ba3565f7',110650,0), ('245bdfd4',110650,0), ('eec8c7ea',110650,0), ('a0e69f57',110650,1), ('64918c77',110650,0), ('d5ae5d5e',110650,0), ('e3bb15a9',110650,0), ('de428da1',110650,0), ('19fe87df',110650,3), ('77fb4336',110650,1), ('6425e683',110650,0), ('e3486bb1',110650,0), ('0b1fb68',110650,0), ('67851210',110650,0), ('19fbd925',110650,0), ('93642a9f',110650,0), ('e4495688',110650,0), ('2106aff',110650,0), ('26c24b41',110650,0), ('d06d8531',110650,0), ('c55ac52',110650,0), ('389a5046',110650,0), ('82d889ac',110650,0), ('d1396868',110650,0), ('3e422761',110650,0), ('997bea1',110650,0), ('6ce601b',110650,0), ('3ea7fdb5',110650,0), ('17fc8aa9',110650,0), ('dc7b87ce',110650,1), ('1b6a14b9',110650,0), ('ef147224',110650,0), ('856d778',110650,1), ('43513514',110650,0), ('734a7c3',110650,0), ('5f70f930',110650,0), ('d2fdbe24',110650,0), ('a85031cd',110650,0), ('40f34c6',110650,1), ('2f957a34',110650,0), ('639bf9d9',110650,0), ('a44c277a',110650,1), ('109dfa63',110650,0), ('81581bb',110650,0), ('48d13a7e',110650,0), ('fd3d4cb0',110650,0), ('5c59787',110650,0), ('f514ec24',110650,0), ('d4f239cf',110650,0), ('c1a2d38',110650,0), ('ed31f5',110650,0), ('cbf3eab0',110650,0), ('e9fcc22f',110650,0), ('7b8ab5c0',110650,0), ('edae084',110650,0), ('5330ae99',110650,1), ('b763b6d',110650,0), ('30779294',110650,0), ('46a07fb',110650,0), ('d7c0786e',110650,0), ('ba6e6964',110650,0), ('eb7f77c8',110650,0), ('5f7346a8',110650,1), ('da68752f',110650,0), ('4f2a428a',110650,0), ('7924ea91',110650,0), ('c7ed5254',110650,0), ('166e951d',110650,0), ('235a5f',110650,0), ('d8dec347',110650,0), ('d61cd335',110650,0), ('aebe7323',110650,1), ('69c3b0bc',110650,0), ('705c34b0',110650,0), ('c95cd32b',110650,0), ('ee1de6d',110650,0), ('2c484e28',110650,1), ('cf7e23f1',110650,1), ('d98b9266',110650,1), ('882e96eb',110650,0), ('83cb33d',110650,0), ('624963c8',110650,1), ('cbc220db',110650,0), ('ac55fef0',110650,0), ('cbdf8ce',110650,0), ('b1aa13b3',110650,0), ('63263',110650,1), ('1f579f8c',110650,0), ('c16a478',110650,0), ('3efb8e11',110650,0), ('55e9b29',110650,0), ('a42348d9',110650,0), ('a0428824',110650,0), ('8646e4d8',110650,0), ('b150e229',110650,1), ('6bb12f31',110650,0), ('e9ae6fa0',110650,0), ('6bd19f59',110650,0), ('49aebdf',110650,1), ('369746fd',110650,0), ('179dc183',110650,0), ('57c273fc',110650,0), ('47cae022',110650,2), ('ed3abe4',110650,0), ('f09358ba',110650,1), ('8c4a9f70',110650,0), ('2a137ee',110650,1), ('786fbcfb',110650,0), ('63fa915d',110650,0), ('4e6edad1',110650,0), ('f79acbd9',110650,0), ('88ca210',110650,4), ('95a459c',110650,0), ('c665fb1f',110650,0), ('9369d5f',110650,0), ('68a18862',110650,1), ('457dddb',110650,0), ('52e280',110650,0), ('36bec281',110650,1), ('9b2f516',110650,0), ('25d215d2',110650,0), ('65f94ea5',110650,0), ('6c85f0b3',110650,1), ('4614d048',110650,0), ('f844c45',110650,a), ('8e135a7',110650,0), ('90a41435',110650,0), ('cbd1daba',110650,0), ('ca6a9b45',110650,0), ('18186b49',110650,0), ('4fde729e',110650,1), ('2276823',110650,1), ('22fbf83b',110650,0), ('206c179f',110650,0), ('586ad440',110650,0), ('1fea486b',110650,0), ('21db465',110650,0), ('57bce47c',110650,0), ('3b6d5a4',110650,1), ('5cc1cb1f',110650,0), ('61811c24',110650,0), ('1e19337b',110650,2), ('2f9ac73',110650,0), ('b626a940',110650,0), ('ab2411',110650,0), ('86f9ea41',110650,0), ('4df6684',110650,0), ('83b857de',110650,0), ('a2c32182',110650,0), ('97f6e25',110650,0), ('b9618744',110650,1), ('64841127',110650,1), ('7e35d82c',110650,0), ('ed14e192',110650,0), ('f9662ba2',110650,0), ('32d0e5e9',110650,0), ('a9a89098',110650,0), ('ed7ac5c2',110650,0), ('3b80cb6c',110650,0), ('8fa54651',110650,0), ('ede9f66',110650,1), ('c1a7a6b1',110650,0), ('9d13a54',110650,0), ('5a5226d',110650,0), ('4bb6ec7',110650,0);
						//org.postgresql.util.PSQLException: ERROR: column "d" does not exist
						 // Position: 98
						nbResult = stmt.executeUpdate(sqlQuery);
					} catch (SQLException e) {
						e.printStackTrace();
					}
				}
				if(buildPairs.size()>0) {
					pairInsert = GSBURLUtil.implode(buildPairs.toArray(), ", ");
					if(type.getId() == GSBModeEnum.GSB_ADD.getId()) {
						sqlQuery = "INSERT INTO "+dbPrefix+"\""+listName+"_"+type.getName()+"_prefixes"+"\""+" (Hostkey, Prefix) VALUES "+pairInsert+";";
					}
					else if(type.getId() == GSBModeEnum.GSB_SUB.getId()) {
						sqlQuery = "INSERT INTO "+dbPrefix+"\""+listName+"_"+type.getName()+"_prefixes"+"\""+" (Hostkey, AddChunkNum, Prefix) VALUES "+pairInsert+";";
					}
					try{
						//INSERT INTO "googpub-phish-shavar_sub_prefixes" (Hostkey, AddChunkNum, Prefix) VALUES (22472631,9818,73618e5), (40e8dc94,9818,4b874d5);
						
						//INSERT INTO "googpub-phish-shavar_add_prefixes" (Hostkey, Prefix) VALUES (219a7890,46c6bf64), (e23fa38e,664e6242), (ef9adeca,b43cc323), (d4ad8438,7359a826), (7778eb5,e845d7f6), (6e3e242c,f980d44), (e4eb731f,95efad5c), (60943b34,60e8e949), (f2cf960,c73218a8), (b3541c22,e05ee2c9), (2a41ea22,7164d0ed), (4b388572,58a24cc), (2f679090,45c39b8e), (ab1af8f1,21ba95f3), (c76a9282,93f1c695), (9b85349,3c2d3d6d), (f8353c41,4135d3), (822f6125,5d7d8db1), (e60403e,a6d29d76), (e60403e,7999fd5), (f145950,851efc4), (775b97d6,8b6d737a), (4d7c5e23,f9d1799f), (4d7c5e23,316c317e);
						//org.postgresql.util.PSQLException: ERROR: syntax error at or near "a7890"
						//  Position: 78
						stmt = con.createStatement();
						System.out.println(sqlQuery);
						nbResult = stmt.executeUpdate(sqlQuery);
					}
					catch (SQLException e) {
						e.printStackTrace();
					}
				}
			}
			else {
				//COULD NOT SAVE
				System.out.println("COULD NOT SAVE.");
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
	 * Enum the GSB\'s list
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
		//googpub-phish-shavar
		//goog-malware-shavar
		/*
		 * CREATE TABLE IF NOT EXISTS "goog-malware-shavar_add_hosts" (
Hostkey varchar(11) NOT NULL,
ChunkNum integer  NOT NULL,
Count varchar(11) NOT NULL,
FullHash varchar(11) DEFAULT NULL
);
CREATE INDEX idx_goog_malware_shavar_add_hosts_Hostkey ON "goog-malware-shavar_add_hosts" USING btree(Hostkey); 
		 */
		
		queries.add("CREATE TABLE IF NOT EXISTS "+dbPrefix+"\"goog-malware-shavar_add_hosts\" (\n"+
				"Hostkey varchar(11) NOT NULL,\n"+
				"ChunkNum integer  NOT NULL,\n"+
				"Count varchar(11) NOT NULL,\n"+
				"FullHash varchar(11) DEFAULT NULL\n"+
				");\n"+
				"DROP INDEX IF EXISTS  idx_"+ "goog_malware_shavar_add_hosts" + "_Hostkey;"+
				"CREATE INDEX idx_"+ "goog_malware_shavar_add_hosts" + "_Hostkey ON "+ "\"goog-malware-shavar_add_hosts\""+" USING btree(Hostkey); ");

		
		queries.add("CREATE TABLE IF NOT EXISTS "+dbPrefix+"\"goog-malware-shavar_add_index\" ("+
				"ChunkNum integer  NOT NULL,\n"+
				"Chunklen integer  NOT NULL\n"+
				");\n"+
				"DROP INDEX IF EXISTS  idx_"+ "goog_malware_shavar_add_index" + "_ChunkNum;"+
				"CREATE INDEX idx_"+ "goog_malware_shavar_add_index" + "_ChunkNum ON "+ "\"goog-malware-shavar_add_index\""+" USING btree(ChunkNum); ");

		
		queries.add("CREATE TABLE IF NOT EXISTS "+dbPrefix+"\"goog-malware-shavar_add_prefixes\" (\n"+
				"Hostkey varchar(11) NOT NULL,\n"+
				"Prefix varchar(11) NOT NULL,\n"+
				"FullHash varchar(11) DEFAULT NULL\n"+
				") ;\n"+
				"DROP INDEX IF EXISTS  idx_"+ "goog_malware_shavar_add_prefixes" + "_Hostkey;"+
				"CREATE INDEX idx_"+ "goog_malware_shavar_add_prefixes" + "_Hostkey ON "+ "\"goog-malware-shavar_add_prefixes\""+" USING btree(Hostkey); ");

		
		queries.add("CREATE TABLE IF NOT EXISTS "+dbPrefix+"\"goog-malware-shavar_sub_hosts\" (\n"+
				"Hostkey varchar(11) NOT NULL,\n"+
				"Chunknum integer  NOT NULL,\n"+
				"Count varchar(11) NOT NULL,\n"+
				"FullHash varchar(11) DEFAULT NULL\n"+
				");\n"+
				"DROP INDEX IF EXISTS  idx_"+ "goog_malware_shavar_sub_hosts" + "_Hostkey;"+
				"CREATE INDEX idx_"+ "goog_malware_shavar_sub_hosts" + "_Hostkey ON "+ "\"goog-malware-shavar_sub_hosts\""+" USING btree(Hostkey); ");

		
		queries.add("CREATE TABLE IF NOT EXISTS "+dbPrefix+"\"goog-malware-shavar_sub_index\" (\n"+
				"ChunkNum integer  NOT NULL,\n"+
				"Chunklen integer  NOT NULL\n"+
				");\n"+
				"DROP INDEX IF EXISTS  idx_"+ "goog_malware_shavar_sub_index" + "_ChunkNum;"+
				"CREATE INDEX idx_"+ "goog_malware_shavar_sub_index" + "_ChunkNum ON "+ "\"goog-malware-shavar_sub_index\""+" USING btree(ChunkNum); ");

		queries.add("CREATE TABLE IF NOT EXISTS "+dbPrefix+"\"goog-malware-shavar_sub_prefixes\" (\n"+
				"Hostkey varchar(11) NOT NULL,\n"+
				"AddChunkNum integer  NOT NULL,\n"+
				"Prefix varchar(11) NOT NULL,\n"+
				"FullHash varchar(11) DEFAULT NULL\n"+
				");\n"+
				"DROP INDEX IF EXISTS  idx_"+ "goog_malware_shavar_sub_prefixes" + "_Hostkey;"+
				"CREATE INDEX idx_"+ "goog_malware_shavar_sub_prefixes" + "_Hostkey ON "+ "\"goog-malware-shavar_sub_prefixes\""+" USING btree(Hostkey); ");

		//googpub-phish-shavar
		queries.add("CREATE TABLE IF NOT EXISTS "+dbPrefix+"\"googpub-phish-shavar_add_hosts\" (\n"+
				"Hostkey varchar(11) NOT NULL,\n"+
				"ChunkNum integer  NOT NULL,\n"+
				"Count varchar(11) NOT NULL,\n"+
				"FullHash varchar(11) DEFAULT NULL\n"+
				");\n"+
				"DROP INDEX IF EXISTS  idx_"+ "googpub_phish_shavar_add_hosts" + "_Hostkey;"+
				"CREATE INDEX idx_"+ "googpub_phish_shavar_add_hosts" + "_Hostkey ON "+ "\"googpub-phish-shavar_add_hosts\""+" USING btree(Hostkey); ");

		queries.add("CREATE TABLE IF NOT EXISTS "+dbPrefix+"\"googpub-phish-shavar_add_index\" (\n"+
				"ChunkNum integer  NOT NULL,\n"+
				"Chunklen integer  NOT NULL\n"+
				");\n"+
				"DROP INDEX IF EXISTS  idx_"+ "googpub_phish_shavar_add_index" + "_ChunkNum;"+
				"CREATE INDEX idx_"+ "googpub_phish_shavar_add_index" + "_ChunkNum ON "+ "\"googpub-phish-shavar_add_index\""+" USING btree(ChunkNum); ");

		queries.add("CREATE TABLE IF NOT EXISTS "+dbPrefix+"\"googpub-phish-shavar_add_prefixes\" (\n"+
				"Hostkey varchar(11) NOT NULL,\n"+
				"Prefix varchar(11) NOT NULL,\n"+
				"FullHash varchar(11) DEFAULT NULL\n"+
				");\n"+
				"DROP INDEX IF EXISTS  idx_"+ "googpub_phish_shavar_add_prefixes" + "_Hostkey;"+
				"CREATE INDEX idx_"+ "googpub_phish_shavar_add_prefixes" + "_Hostkey ON "+ "\"googpub-phish-shavar_add_prefixes\""+" USING btree(Hostkey); ");

		queries.add("CREATE TABLE IF NOT EXISTS "+dbPrefix+"\"googpub-phish-shavar_sub_hosts\" (\n"+
				"Hostkey varchar(11) NOT NULL,\n"+
				"ChunkNum integer  NOT NULL,\n"+
				"Count varchar(11) NOT NULL,\n"+
				"FullHash varchar(11) DEFAULT NULL\n"+
				");\n"+
				"DROP INDEX IF EXISTS  idx_"+ "googpub_phish_shavar_sub_hosts" + "_Hostkey;"+
				"CREATE INDEX idx_"+ "googpub_phish_shavar_sub_hosts" + "_Hostkey ON "+ "\"googpub-phish-shavar_sub_hosts\""+" USING btree(Hostkey); ");

		queries.add("CREATE TABLE IF NOT EXISTS "+dbPrefix+"\"googpub-phish-shavar_sub_index\" (\n"+
				"ChunkNum integer  NOT NULL,\n"+
				"ChunkLen integer  NOT NULL\n"+
				");\n"+
				"DROP INDEX IF EXISTS  idx_"+ "googpub_phish_shavar_sub_index" + "_ChunkNum;"+
				"CREATE INDEX idx_"+ "googpub_phish_shavar_sub_index" + "_ChunkNum ON "+ "\"googpub-phish-shavar_sub_index\""+" USING btree(ChunkNum); ");

		queries.add("CREATE TABLE IF NOT EXISTS "+dbPrefix+"\"googpub-phish-shavar_sub_prefixes\" (\n"+
				"Hostkey varchar(11) NOT NULL,\n"+
				"AddChunkNum varchar(11) NOT NULL,\n"+
				"Prefix varchar(11) NOT NULL,\n"+
				"Fullhash varchar(11) DEFAULT NULL\n"+
				");\n"+
				"DROP INDEX IF EXISTS  idx_"+ "googpub_phish_shavar_sub_prefixes" + "_Hostkey;"+
				"CREATE INDEX idx_"+ "googpub_phish_shavar_sub_prefixes" + "_Hostkey ON "+ "\"googpub-phish-shavar_sub_prefixes\""+" USING btree(Hostkey); ");
		try {
			Statement stmt = con.createStatement();
			for(String query : queries){
				System.out.println(query);
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
