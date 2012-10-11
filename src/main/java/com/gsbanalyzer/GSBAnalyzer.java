package com.gsbanalyzer;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import com.gsbanalyzer.gsb.models.GSBEntry;
import com.gsbanalyzer.gsb.models.GSBInfectedUrl;
import com.gsbanalyzer.gsb.models.GSBListEnum;
import com.gsbanalyzer.gsb.models.GSBUrl;
import com.gsbanalyzer.util.Utils;

/**
 * GSB Wrapper - Analyzer
 * Allowed to test a list of URLs with Google Safe Browsing.
 * You need to build a database with GSB Wrapper - Crawler before use this wrapper.
 * @author Julien SOSIN. 
 */
public class GSBAnalyzer {

	//GSB
	private List<GSBListEnum> listGSB;
	private String gsbKey;
	private String gsbUrl;
	public static String gsbPhishingList = "googpub-phish-shavar";
	public static String gsbMalwareList = "goog-malware-shavar";
	public static char gsbAddChunk = 'a';
	public static char gsbSubChunk = 's';
	public static String gsbAppVersion = "1.5.2";
	public static String gsbApiVersion = "2.2";

	public static final String RESULT_PHISHING = "malware";
	public static final String RESULT_MALWARE = "phishing";
	public final int ID_GOOG_MALWARE_SHAVAR = 1;
	public final int ID_GOOG_REGTEST_SHAVAR = 2;
	public final int ID_GOOG_WHITEDOMAIN_SHAVAR = 3;
	public final int ID_GOOGPUB_PHISH_SHAVAR = 4;

	//DB 
	private Connection con;
	private String prefix;
	private String dbUrl;
	private String dbUsername;
	private String dbPassword;	

	/**
	 * Instance a new GSB Wrapper
	 * Allowed to test a list of URLs with Google Safe Browsing.
	 * You need to build a database with GSB Wrapper - Crawler before use this wrapper.
	 * @param gsbKey : The key provided by GSB
	 * @param gsbUrl : http://safebrowsing.clients.google.com/safebrowsing/downloads by default
	 * @param dbPrefix : Prefix you will use in YOUR database
	 * @param dbUrl : The database url use by jdbc Example : jdbc:mysql://localhost/gsb
	 * @param dbUsername : The database's username
	 * @param dbPassword : The database's password
	 */
	public GSBAnalyzer(String gsbKey, String gsbUrl, String prefix, String dbUrl, String dbUsername, String dbPassword) {
		super();
		this.gsbKey = gsbKey;
		this.gsbUrl = gsbUrl;
		this.prefix = prefix;
		this.dbUrl = dbUrl;
		this.dbUsername = dbUsername;
		this.dbPassword = dbPassword;
		listGSB = new ArrayList<GSBListEnum>();
		listGSB.add(GSBListEnum.GSB_MALWARE_LIST);
		listGSB.add(GSBListEnum.GSB_PHISHING_LIST);
		try {
			con = DriverManager.getConnection (this.dbUrl,this.dbUsername,this.dbPassword);
			Class.forName("com.mysql.jdbc.Driver");
		} catch (SQLException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
	}

	private List<GSBListEnum> getListGSB() {
		return listGSB;
	}

	/**
	 * Check a list of domains with GSB
	 * @param domains list of domains to check
	 * @return list of GSBInfected urls
	 */
	public List<GSBInfectedUrl> analyzeWithGSB(List<String> domains) {
		return analyzeURLs(makeHostKey(domains));
	}

	/**
	 * Analyze URLs with GSB and write reports
	 * @param urls : list of domains usable by GSB
	 */
	private List<GSBInfectedUrl> analyzeURLs(List<GSBEntry> urls){
		List<GSBInfectedUrl> res = new ArrayList<GSBInfectedUrl>();

		if(urls.size()<1) return res;

		String hostkey;
		String[] split;
		String fullhashRes = "";
		String buildtrunk = "";
		Integer count = 0;
		String sqlQuery;
		StringBuilder hostkeys;
		StringBuilder prefixes;
		List<GSBEntry> matchingHostkeys;
		GSBUrl canUrl;
		List<GSBEntry> variations;
		Statement stmt;
		ResultSet rs;
		try {
			stmt = con.createStatement();
			for(GSBListEnum gsbenum : getListGSB()) {
				matchingHostkeys = new ArrayList<GSBEntry>();
				hostkeys = new StringBuilder();
				prefixes = new StringBuilder();
				buildtrunk = gsbenum.getName()+"-add";
				//Loop over each list
				for(GSBEntry url : urls){
					//We check prefixes
					hostkeys.append("`Hostkey` = '"+url.getPrefix()+"' OR ");
					prefixes.append("`Prefix` = '"+url.getPrefix()+"' OR ");
				}
				//Check Hostkeys
				sqlQuery = "SELECT DISTINCT Hostkey, Count FROM `"+prefix+buildtrunk+"-hosts` WHERE "+hostkeys.substring(0, hostkeys.length()-4);
				rs = stmt.executeQuery(sqlQuery);
				while(rs.next()){
					for(GSBEntry url : urls){
						if(url.getPrefix().equals(rs.getString("Hostkey"))){
							//We count how many prefixes have this hostkey
							hostkey = (String) rs.getString("Hostkey");
							try{
								count = rs.getInt("Count");
							}
							catch(NumberFormatException e){
								e.printStackTrace();
							}
							//We have to get all prefixes if count > 0
							if(count > 0){
								//There was a match and the count is more than one so there are prefixes!
								//Hash up a load of prefixes and create the build query if we haven't done so already
								canUrl = GSBURLUtil.Canonicalize(url.getDomain());
								variations = makePrefixes(canUrl.getParts().getHost(),canUrl.getParts().getPath(),canUrl.getParts().getQuery(),canUrl.getParts().getusingIP());
								//We add entries to urls to test
								for(GSBEntry entry : variations){
									prefixes.append("`Prefix` = '"+entry.getPrefix()+"' OR ");
								}
								sqlQuery = "SELECT Hostkey, Prefix FROM `"+prefix+buildtrunk+"-prefixes` WHERE ("+(prefixes.substring(0, prefixes.length()-4))+") AND `Hostkey` = '"+hostkey+"'";
								rs = stmt.executeQuery(sqlQuery);
								while(rs.next()){
									for(GSBEntry variation : variations){
										if(variation.getPrefix().equals(rs.getString("Prefix"))){
											variation.setPrefix(rs.getString("Prefix"));
											variation.setHostkey(rs.getString("Hostkey"));
											matchingHostkeys.add(variation);
										}
									}
								}
							}
							else{
								if(url.getPrefix().equals(hostkey)){
									url.setHostkey(hostkey);
									matchingHostkeys.add(url);
								}
							}
						}
					}
				}
				if(matchingHostkeys.size()>0){
					//Ask GSB for Fullhash check
					fullhashRes = doFullLookup(matchingHostkeys);
					split = fullhashRes.split("\n");
					//We compare with matchingHostkeys to test if they are in the GSB's fullhash response
					for(int i=1;i<split.length;i++){
						for(GSBEntry matchingHostkey : matchingHostkeys){
							if(matchingHostkey.getFullhash().equals(GSBURLUtil.convertASCIIToHex(split[i]))){
								res.add(new GSBInfectedUrl(matchingHostkey.getDomain(), gsbenum.getType(), true));
								matchingHostkey.setFullhash(""); //We check this matching hostkey
								break;
							}
						}
					}	
					//We add unverified matchinghostkeys
					for(GSBEntry matchingHostkey : matchingHostkeys){
						if(!matchingHostkey.getFullhash().isEmpty())
							res.add(new GSBInfectedUrl(matchingHostkey.getDomain(), gsbenum.getType(), false));
					}
				}
			}
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return res;
	}

	private String doFullLookup(List<GSBEntry> matchingPrefixes) {
		String url = this.gsbUrl+"/gethash?client=api"+"&apikey="+gsbKey+"&appver="+gsbAppVersion+"&pver="+gsbApiVersion;
		return GSBURLUtil.downloadFullHash(url, matchingPrefixes);
	}

	/*Make URL prefixes for use after a hostkey check*/
	private List<GSBEntry> makePrefixes(String host, String path, String query, boolean usingip){  
		//Exact hostname in the url
		HashSet set = new HashSet();
		String[] pathparts = null;
		String pathiparts;
		List<String> topslice;
		int maxslice = 0;
		int upperLimit = 0;
		int i=0;
		List<String> hostcombos = new ArrayList<String>();
		List<String> variations = new ArrayList<String>();
		List<String> backhostparts = new ArrayList<String>();
		hostcombos.add(host);
		if(!usingip){
			backhostparts = Arrays.asList(host.split("\\."));
			Collections.reverse(backhostparts);
			if(backhostparts.size()>5) {
				maxslice = 5;
			}
			else {
				maxslice = backhostparts.size();
			}
			topslice = backhostparts.subList(0, maxslice-1);
			while(maxslice>1) {
				Collections.reverse(topslice);
				hostcombos.add(GSBURLUtil.implode(topslice.toArray(), "."));
				maxslice--;
				topslice = backhostparts.subList(0, maxslice-1);
			}
		}
		//Equivalent to Array unique in PHP
		set.addAll(hostcombos);
		hostcombos = new ArrayList<String>(set);

		if(!path.isEmpty()) {
			pathparts = path.split("/");
			if(pathparts.length>4) {
				upperLimit = 4;
			}
			else {
				upperLimit = pathparts.length;
			}
		}
		for(String hostCombo : hostcombos) {
			if(!path.isEmpty()) {
				i = 0;
				pathiparts = "";
				while(i<upperLimit){
					if(i!=(pathparts.length-1)) {
						pathiparts = pathiparts+pathparts[i]+"/";
					}
					else {
						pathiparts = pathiparts+pathparts[i]+"/";
					}
					variations.add(new String(hostCombo+pathiparts));
					i++;
				}
			}
		}
		return makeHashes(variations);
	}

	/**
	 * Checks to see if a match for a prefix is found in the sub table, if it is then we won't do
	 *  a full-hash lookup. Return true on match in sub list, return false on negative
	 * @param listname
	 * @param prefixlist
	 * @param mode
	 * @return
	 */
	private boolean subCheck(String listname, List<Map<String, String>> prefixlist, String mode){
		String buildtrunk = listname+"-sub";
		String sqlQuery;
		List<Object[]> result; 
		Statement stmt;
		ResultSet rs;
		try {
			stmt = con.createStatement();
			if(mode.equals("prefix")) {
				//Mode is prefix so the add part was a prefix, not a hostkey so we just check prefixes (saves a lookup)
				for(Map<String, String> value : prefixlist){
					sqlQuery = "SELECT * FROM `"+prefix+buildtrunk+"-prefixes` WHERE `Prefix` = '"+(String)value.get(0)+"'";
					rs = stmt.executeQuery(sqlQuery);
					while(rs.next()){
						if(Integer.parseInt(rs.getString(1),16) == Integer.valueOf(value.get(1)) ) {
							return true;
						}
					}
				}
			}
			else if(mode.equals("hostkey")){
				//Mode is hostkey
				for(Map<String, String> value : prefixlist){
					sqlQuery = "SELECT * FROM `"+prefix+buildtrunk+"-prefixes` WHERE `Hostkey` = '"+(String)value.get("Hostkey")+"'";
					rs = stmt.executeQuery(sqlQuery);
					while(rs.next()){
						if(rs.getString(0).equals(value.get("Hostkey"))) {
							return true;
						}
					}
				}
			}
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return false;
	}

	/**
	 * Hash up a list of values from makePrefixes() (will possibly be
	 * combined into that function at a later date
	 * @param prefixArray
	 * @return
	 */
	private List<GSBEntry> makeHashes(List<String> prefixArray) {
		String fullhash;
		List<GSBEntry> returnPrefixes = new ArrayList<GSBEntry>();
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		if(prefixArray.size()>0){
			for(String value : prefixArray){
				fullhash = GSBURLUtil.bytes2Hex(md.digest((value).getBytes()));
				returnPrefixes.add(new GSBEntry(value,fullhash.substring(0, 8),fullhash));
			}
		}
		return returnPrefixes;
	}       

	/**
	 * Check database for any cached full-length hashes for a given prefix.
	 * Return a list of FullHash and a ChunkNum
	 **/
	private List<String> cacheCheck(String hostKey) {
		String buildtrunk;
		String sqlQuery;
		List<Object[]> resulttwo;
		List<String> res;
		Statement stmt;
		ResultSet rs;
		ResultSet rs2;
		try {
			stmt = con.createStatement();
			for(GSBListEnum gsbenum : getListGSB()) {
				buildtrunk = gsbenum.getName()+"-add";
				sqlQuery = "SELECT * FROM `"+prefix+buildtrunk+"-hosts` WHERE `Hostkey` = '"+hostKey+"' AND `FullHash` != ''";
				rs = stmt.executeQuery(sqlQuery);
				if(rs.last()){
					while(rs.next()){
						res = new ArrayList<String>();
						res.add(rs.getString(1));
						res.add(rs.getString(3));
						return res;
					}
				}else{
					sqlQuery = "SELECT * FROM `"+prefix+buildtrunk+"-prefixes` WHERE `Prefix` = '"+hostKey+"' AND `FullHash` != ''";
					rs = stmt.executeQuery(sqlQuery);
					while(rs.next()){
						sqlQuery = "SELECT * FROM `"+prefix+buildtrunk+"-hosts` WHERE `Hostkey` = '"+hostKey+"' AND `FullHash` != ''";
						rs2 = stmt.executeQuery(sqlQuery);
						while(rs2.next()){
							if(rs.getInt(2)>0){
								res = new ArrayList<String>();
								res.add(rs.getString(1));
								res.add(rs.getString(3));
								return res;
							}
						}
					}
				}
			}
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Process data provided from the response of a full-hash GSB
	 *request
	 **/
	private Map<String, Map<String, String>> processFullLookup(List<Integer> result) {
		List<List<Integer>> splitHead;
		String[] chunkInfo;
		String listName;
		String addChunk;
		Integer chunkLen;
		String chunkData;
		List<Integer> cloneData = (List<Integer>) ((ArrayList<Integer>)result).clone();
		Map<String, String> tmp;
		Map<String,Map<String,String>> extractHash = new HashMap<String, Map<String,String>>();
		while(cloneData.size()>0) {
			splitHead = Utils.splitList(cloneData,'\n', 2);
			chunkInfo = Utils.listInt2String(splitHead.get(0)).split(":");
			listName = chunkInfo[0];
			addChunk = chunkInfo[1];
			chunkLen = Integer.valueOf(chunkInfo[2]);
			chunkData = Utils.getHexFromUnsignedByteList(splitHead.get(1),0,chunkLen);
			while(chunkData.length()>0) {
				tmp = new HashMap<String, String>();
				tmp.put(addChunk, chunkData.substring(0,63));
				extractHash.put(listName,tmp);

			}
			cloneData = splitHead.get(1).subList(chunkLen, splitHead.size());
		}
		return extractHash;
	}

	/**
	 * Add a full-hash key to a prefix or hostkey (the variable is $prefix but it could
	 *be either).
	 */
	private void addFullHash(String prefix, String chunkNum, String fullHash, String listName) {
		int queryResult = 0;
		String sqlQuery;
		String sqlQuery2;
		String buildTrunk = listName+"-add";
		Statement stmt;
		ResultSet rs;
		ResultSet rs2;
		try {
			stmt = con.createStatement();
			//First check hosts
			sqlQuery = "SELECT * FROM `"+prefix+buildTrunk+"-hosts` WHERE `Hostkey` = '"+prefix+"' AND `Chunknum` = '"+chunkNum+"'";
			rs = stmt.executeQuery(sqlQuery);
			if(rs.last()) {
				while(rs.next()){
					if(rs.getObject(4) != null) {
						if(!(rs.getString(4)).isEmpty()) {
							//We've got a live one! Insert the full hash for it   
							sqlQuery = "UPDATE `"+buildTrunk+"-hosts` SET `FullHash` = '"+fullHash+"' WHERE `ID` = '"+rs.getString(0)+"'";
							stmt.execute(sqlQuery);
						}
					}
				}
			}
			else {
				//If there are no rows it must be a prefix      
				sqlQuery = "SELECT * FROM `"+prefix+buildTrunk+"-prefixes` WHERE `Prefix` = '"+prefix+"'";
				rs = stmt.executeQuery(sqlQuery);
				while(rs.next()){
					if(rs.getString(4) != null) {
						if(!(rs.getString(4)).isEmpty()) {
							sqlQuery2 = "SELECT * FROM `"+prefix+buildTrunk+"-hosts` WHERE `Hostkey` = '"+rs.getString(1)+"' AND `Chunknum` = '"+chunkNum+"'";
							rs2 = stmt.executeQuery(sqlQuery);
							while(rs2.next()){
								if(Integer.parseInt(rs2.getString(3),16)>0) {
									sqlQuery = "UPDATE `"+buildTrunk+"-prefixes` SET `FullHash` = '"+fullHash+"'";
									stmt.execute(sqlQuery);
								}
							}
						}
					}
				}
			}
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Convert domains (like http://ianfette.org/) into GSB Prefixes
	 * We compare the prefix with the DB and if we found a match, we lookup on GSB and
	 * ask for a fullhash to execute a fullmatch
	 * @param domains : list of domains
	 * @return list of GSB usable Hostkeys
	 */

	public List<GSBEntry> makeHostKey(List<String> domains){
		String fullhash;
		List<GSBEntry> returnhosts = new ArrayList<GSBEntry>();
		List<String> hosts;
		MessageDigest md = null;
		GSBUrl canUrl;
		String url;
		boolean usingip;
		for(String domain : domains){
			hosts = new ArrayList<String>();
			canUrl = GSBURLUtil.Canonicalize(domain);
			if(canUrl != null){
				url = canUrl.getGSBUrl();
				usingip = canUrl.getParts().getusingIP();
				try {
					md = MessageDigest.getInstance("SHA-256");
				} catch (NoSuchAlgorithmException e) {
					e.printStackTrace();
				}
				if(usingip) {           
					hosts.add(url+"/");
				}
				else{
					List<String> hostparts = Arrays.asList(url.split("/")[0].split("\\."));
					Collections.reverse(hostparts);
					if(hostparts.size()>4){
						List<String> fiveparts = hostparts.subList(0, 5);
						Collections.reverse(fiveparts);
						hosts.add(GSBURLUtil.implode(fiveparts.toArray(), ".")+"/");
						Collections.reverse(fiveparts);
					}
					if(hostparts.size()>3){
						List<String> fourparts = hostparts.subList(0, 4);
						Collections.reverse(fourparts);
						hosts.add(GSBURLUtil.implode(fourparts.toArray(), ".")+"/");
						Collections.reverse(fourparts);
					}
					if(hostparts.size()>2){
						List<String> threeparts = hostparts.subList(0, 3);
						Collections.reverse(threeparts);
						hosts.add(GSBURLUtil.implode(threeparts.toArray(), ".")+"/");
						Collections.reverse(threeparts);
					}
					if(hostparts.size()>1){
						List<String> twoparts = hostparts.subList(0, 2);
						Collections.reverse(twoparts);
						hosts.add(GSBURLUtil.implode(twoparts.toArray(), ".")+"/");
						Collections.reverse(twoparts);
					}
				}
			}
			//Now make key & key prefix
			for(String host : hosts) {	
				fullhash = GSBURLUtil.bytes2Hex(md.digest((host).getBytes()));
				//We create add the domain with the original URL because we have to use it after 
				returnhosts.add(new GSBEntry(domain, fullhash.substring(0,8), fullhash));
			}
		}
		return returnhosts;
	}

	public String getDbUrl() {
		return dbUrl;
	}

	public void setDbUrl(String dbUrl) {
		this.dbUrl = dbUrl;
	}

	public String getDbUsername() {
		return dbUsername;
	}

	public void setDbUsername(String dbUsername) {
		this.dbUsername = dbUsername;
	}

	public String getDbPassword() {
		return dbPassword;
	}

	public void setDbPassword(String dbPassword) {
		this.dbPassword = dbPassword;
	}


}