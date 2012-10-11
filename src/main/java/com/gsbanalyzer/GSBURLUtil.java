package com.gsbanalyzer;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.IDN;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.gsbanalyzer.exceptions.GSBException;
import com.gsbanalyzer.gsb.models.GSBEntry;
import com.gsbanalyzer.gsb.models.GSBUrl;
import com.gsbanalyzer.gsb.models.GSBUrlParts;
import com.gsbanalyzer.util.Utils;

public class GSBURLUtil {

	private static GSBURLEncoder codec = new GSBURLEncoder();
	private static String IPValidation = "^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$";

	/**
	 * Canonicalize a full URL according to Google's definition.
	 * 
	 **/
	public static GSBUrl Canonicalize(String url){
		String hostnameip;
		String usehost;
		String finalUrl;
		String append = "";
		String canurl = "";
		String realurl = "";
		List<String> pathparts;
		boolean usingip;
		//Remove line feeds, return carriages, tabs, vertical tabs
		url = url.replace("\\x09", "");
		url = url.replace("\\x0A", "");
		url = url.replace("\\x0D", "");
		url = url.replace("\\x0B", "");
		finalUrl = url.trim();
		//URL Encode for easy extraction
		try {
			finalUrl = canonicalizeURL(finalUrl);
		} catch (GSBException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		//Now extract hostname & path
		List<String> parts = j_parseUrl(finalUrl);
		if(parts == null) return null;
		String userInfo = parts.get(0);
		String hostname = parts.get(1);
		Integer port = Integer.valueOf(parts.get(2));
		String path = parts.get(2);
		String query = parts.get(3);
		String lasthost = "";
		String lastpath = "";
		String lastquery = "";
		//Remove all hex coding (loops max of 50 times to stop craziness but should never
		//reach that)
		for (int i = 0; i < 50; i++) {
			if(hostname==lasthost&&path==lastpath&&query==lastquery)
				break;
			lasthost = hostname;
			lastpath = path;
			lastquery = query;
		}
		//Deal with hostname first
		//Replace all leading and trailing dots
		//		hostname = hostname.replace(".","");
		//Replace all consecutive dots with one dot
		hostname = hostname.replaceAll("/\\.{2,}/", ".");
		//Make it lowercase
		hostname = hostname.toLowerCase();
		//See if its a valid IP
		hostnameip = isValid_IP(hostname);
		if(hostnameip != null){
			usingip = true;
			usehost = hostnameip;
		}
		else{
			usingip = false;
			usehost = hostname;
		}
		//The developer guide has lowercasing and validating IP other way round but its more efficient to
		//have it this way
		//Now we move onto canonicalizing the path
		pathparts =  new ArrayList<String>(Arrays.asList(path.split("/")));
		for(int i=0;i<pathparts.size();i++) {
			if(pathparts.get(i).equals("..")) {
				if(i!=0) {
					pathparts.remove(i-1);
				}
				pathparts.remove(i);
			}
			else if(pathparts.get(i).equals(".")||pathparts.get(i).isEmpty()) {
				pathparts.remove(i);
			}
		}
		path = "/"+implode(pathparts.toArray(), "/");

		usehost = flexURLEncode(usehost,false);
		path = flexURLEncode(path,false);
		if(userInfo != null) {
			if(!userInfo.isEmpty()) {
				realurl = realurl.concat(userInfo+"@");
			}
		}
		canurl = canurl.concat(usehost);
		realurl = realurl.concat(usehost);
		if(port > 0){
			canurl = canurl.concat(":"+port);
			realurl = realurl.concat(":"+port);
		}
		canurl = canurl.concat(path);
		realurl = realurl.concat(path);
		if(substr_count(finalUrl,"?")>0){
			canurl = canurl.concat("?"+query);
			realurl = realurl.concat("?"+query);
		}
		//URL always end with a "/"
		if(!canurl.endsWith("/")) canurl = canurl.concat("/");
		return new GSBUrl(canurl, realurl, new GSBUrlParts(hostname, path, query, usingip));
	}

	/**
	 * Had to write another layer as built in PHP urlencode() escapes all non
	 * alpha-numeric Google states to only urlencode if its below 32 or above
	 * or equal to 127 (some of those are non alpha-numeric and so urlencode
	 * on its own won't work).
	 **/
	public static String flexURLEncode(String url,boolean ignorehash){
		boolean escapePercentRange;
		char percentHex1 = 0;
		char percentHex2 = 0;
		int ascii = 0;
		char[] urlcharsarray = url.toCharArray();
		if(urlcharsarray.length>0){
			for(int i=0;i<urlcharsarray.length;i++){
				ascii = (int) urlcharsarray[i];
				//				System.out.println("i:"+i+" char "+urlcharsarray[i]);
				// If we get a percent, we looks characters after it
				if(urlcharsarray[i] == '%') {
					escapePercentRange = false;
					//					System.out.println("We find a % at "+i);
					for(int j=i+1;j<urlcharsarray.length;j++) {
						//						System.out.println("j:"+j+" "+urlcharsarray[j]);
						if(!isHex(urlcharsarray[j])) {
							//We each a "non percent code" character
							//We test if the two previous character and the % make a percent code
							//							System.out.println("We escape the % range with "+urlcharsarray[j]);
							percentHex1 = urlcharsarray[j-1];
							percentHex2 = urlcharsarray[j-2];
							escapePercentRange = true;
						}
						if(j+1>=urlcharsarray.length) {
							//We have read all 
							percentHex1 = urlcharsarray[j];
							percentHex2 = urlcharsarray[j-1];
							escapePercentRange = true;
						}
						if(escapePercentRange) {
							if((int) percentHex1>=48 && (int) percentHex1<=90 &&
									(int) percentHex2>=48 && (int) percentHex2<=90) {
								urlcharsarray[i] = percentCode2char("%"+percentHex2+percentHex1);
								//We delete the encoded characters
								for(int m=i+1;m<j;m++) {
									urlcharsarray[m] = ' ';
								}
								if(j+1>=urlcharsarray.length) {
									urlcharsarray[j] = ' ';
									urlcharsarray[j-1] = ' ';
								}
								else {
									i = j-1;
								}
								break;
							}
							else {
								//								System.out.println("bug "+urlcharsarray[j-2]+urlcharsarray[j-1]);
							}
						}
					}
				}
				//				if(ascii<=32||ascii>=127||(urlcharsarray[i] == '#' && !ignorehash)||urlcharsarray[i] == '%') {
				//					urlcharsarray[i] = (urlcharsarray[i]);
				//				}
			}
			return Utils.implodeOneChar(urlcharsarray, "");
		}
		else {
			return url;
		}
	}

	public static List<String> j_parseUrl(String url){
		List<String> res = new ArrayList<String>();
		String fragment = "";
		String query = "";
		String file = "";
		String directory = "";
		String drive = "";
		String path = "";
		String relative = "";
		int port = 0;
		String host = "";
		String password = "";
		String user = "";
		String userInfo = "";
		String authority = "";
		String scheme = "";
		String source;
		String strict = "^(?:([^:\\/?#]+):)?(?:\\/\\/\\/?((?:(([^:@]*):?([^:@]*))?@)?([^:\\/?#]*)(?::(\\d*))?))?(((?:\\/(\\w:))?((?:[^?#\\/]*\\/)*)([^?#]*))(?:\\?([^#]*))?(?:#(.*))?)";
		String loose = "^(?:(?![^:@]+:[^:@\\/]*@)([^:\\/?#.]+):)?(?:\\/\\/\\/?)?((?:(([^:@]*):?([^:@]*))?@)?([^:\\/?#]*)(?::(\\d*))?)(((?:\\/(\\w:))?(\\/(?:[^?#](?![^?#\\/]*\\.[^?#\\/.]+(?:[?#]|$)))*\\/?)?([^?#\\/]*))(?:\\?([^#]*))?(?:#(.*))?)";
		Pattern p1 = Pattern.compile(loose);
		Matcher m1 = p1.matcher(url);
		while (m1.find() == true) {
			Pattern p2 = Pattern.compile(strict);
			Matcher m2 = p2.matcher(url);
			while (m2.find() == true) {
				if(m2.group(0) != null) source = m2.group(0);
				if(m2.group(1) != null) scheme = m2.group(1);
				if(m2.group(2) != null)  authority = m2.group(2);
				if(m2.group(3) != null) userInfo = m2.group(3);
				if(m2.group(4) != null) user = m2.group(4);
				if(m2.group(5) != null) password = m2.group(5);
				if(m2.group(6) != null) host = m2.group(6);
				if(m2.group(7) != null) {
					if(!m2.group(7).isEmpty()) {
						port = Integer.valueOf(m2.group(7));
					}
				}
				if(m2.group(8) != null) relative = m2.group(8);
				if(m2.group(9) != null) path = m2.group(9);
				if(m2.group(10) != null) drive = m2.group(10);
				if(m2.group(11) != null) directory = m2.group(11);
				if(m2.group(12) != null) file = m2.group(12);
				if(m2.group(13) != null)  query = m2.group(13);
				if(m2.group(14) != null)  fragment = m2.group(14);
			}
		}
		try {
			//We check if  the TLD doesn't contains number
			String[] splittedHost = host.split("\\.");
			String tld = splittedHost[splittedHost.length-1];
			String regex = "[a-zA-Z]+$";
			Pattern p3 = Pattern.compile(regex);
			Matcher m3 = p3.matcher(tld);
			if(m3.find() == false){
				return null;
			}
			host = IDN.toASCII(host);
			res.add(userInfo);
			res.add(host);
			res.add(String.valueOf(port));
			res.add(path);
			res.add(query);
//			res = new URI(scheme, userInfo, host, port, path, query, fragment);
		} catch (NumberFormatException e) {
			e.printStackTrace();
		}
//		} catch (URISyntaxException e) {
//			logger.error("Can't parse "+url);
//			e.printStackTrace();
//		}
		return res;
	}

	/**
	 * Checks if an IP provided in either hex, octal or decimal is in fact
	 * an IP address. Normalises to a four part IP address.
	 **/
	public static String isValid_IP(String ip){
		String newIp;
		String twoparts;
		String threeparts;
		List<String> hexplode;
		List<String> tmpcomponents;
		//First do a simple check, if it passes this no more needs to be done   
		if(!is_ip(ip))
			return null;

		//Its a toughy... eerm perhaps its all in hex?
		String checkhex = hexIPtoIP(ip);
		if(checkhex != null)
			return checkhex;

		//If we're still here it wasn't hex... maybe a DWORD format?
		//		String checkdword = hexIPtoIP(Integer.toHexString(Integer.valueOf(ip)));
		//		if(checkdword != null)
		//			return checkdword;

		//Nope... maybe in octal or a combination of standard, octal and hex?!
		//		String[] ipcomponents = ip.split(".");
		//		ipcomponents[0] = hexoct2dec(ipcomponents[0]);
		//		if(ipcomponents.length==2){
		//			//The writers of the RFC docs certainly didn't think about the clients! This could be a DWORD mixed with an IP part
		//			if(isInt(ipcomponents[0])&&isInt(ipcomponents[1])){
		//				if(Integer.valueOf(ipcomponents[0])<=255) {
		//					threeparts = Integer.toHexString(Integer.valueOf(ipcomponents[1]));
		//					hexplode = Utils.preg_split("//", threeparts);
		//					if(hexplode.size()>4){
		//						newIp = ipcomponents[0]+"."+iphexdec(hexplode.get(0)+hexplode.get(1))+"."+
		//								iphexdec(hexplode.get(2)+hexplode.get(3))+"."+iphexdec(hexplode.get(4)+hexplode.get(5));
		//						//Now check if its valid
		//						if(is_ip(newIp))
		//							return newIp;
		//					}
		//				}
		//			}       
		//		}
		//		ipcomponents[1] =hexoct2dec(ipcomponents[1]);
		//		if(ipcomponents.length==3){
		//			//Guess what... it could also be a DWORD mixed with two IP parts!
		//			if(isInt(ipcomponents[0])&&isInt(ipcomponents[1])&&isInt(ipcomponents[2])){
		//				if(Integer.valueOf(ipcomponents[0])<=255 && Integer.valueOf(ipcomponents[1])<=255) {
		//					twoparts = Integer.toHexString(Integer.valueOf(ipcomponents[2]));
		//					hexplode = Utils.preg_split("//", twoparts);
		//					if(hexplode.size()>3){
		//						newIp = ipcomponents[0]+"."+ipcomponents[1]+"."+
		//								iphexdec(hexplode.get(0)+hexplode.get(1))+"."+iphexdec(hexplode.get(2)+hexplode.get(3));
		//						//Now check if its valid
		//						if(is_ip(newIp))
		//							return newIp;
		//					}
		//				}
		//			}       
		//		}
		//		//If not it may be a combination of hex and octal
		//		if(ipcomponents.length>=4){
		//			tmpcomponents = new ArrayList<String>();
		//			tmpcomponents.add(ipcomponents[2]);
		//			tmpcomponents.add(ipcomponents[3]);
		//			for(String value : tmpcomponents){
		//				if(!value.equals(hexoct2dec(value))){
		//					return null; 
		//				}
		//			}
		//			tmpcomponents.add(0,ipcomponents[0]);
		//			tmpcomponents.add(1,ipcomponents[1]);
		//
		//			//Convert back to IP form
		//			newIp = implode(tmpcomponents.toArray(),".");
		//
		//			//Now check if its valid
		//			if(is_ip(newIp))
		//				return newIp;
		//		}

		//Well its not an IP that we can recognise... theres only so much we can do!
		return null;
	}

	/**
	 * Regex to check if its a numerical IP address
	 **/
	public static boolean is_ip(String ip){
		if(containsLetter(ip)) {
			return false;
		}
		String [] parts = ip.split ("\\.");
		for (String s : parts){
			int i = Integer.parseInt (s);
			if (i < 0 || i > 255) {
				return false;
			}
		}
		return true;
	} 

	public static boolean containsLetter(String s) {
		if ( s == null )
			return false;
		boolean letterFound = false;
		for (int i = 0; !letterFound && i < s.length(); i++)
			letterFound = letterFound
			|| Character.isLetter(s.charAt(i));
		return letterFound;
	} 

	/*Checks if input is in octal format*/
	public static boolean isOctal(String x){
		//Relys on the fact that in IP addressing octals must begin with a 0 to denote octal
		return x.substring(0,1).equals("0");
	}

	/*Converts hex or octal input into decimal */
	public static String hexoct2dec(String value){
		//As this deals with parts in IP's we can be more exclusive
		if(substr_count(value.substring(0,1),"0x")>0&&isHex(value)){
			return String.valueOf(Integer.parseInt(value,16));
		}
		else if(isOctal(value)){
			return String.valueOf(Integer.parseInt(value,8));  
		}
		else
			return null;
	}

	public static String ltrim(String _string) {
		_string = _string.replaceAll("^ 0", "");
		return _string;
	}

	public static boolean isHex(String string) {
		char[] hexDigitArray = string.toCharArray();
		int hexDigitLength = hexDigitArray.length;

		boolean isNotHex;
		for (int i = 0; i < hexDigitLength; i++) {
			isNotHex = Character.digit(hexDigitArray[i], 16) == -1;
			if (isNotHex) {
				return false;
			}
		}
		return true;
	}

	public static boolean isHex(char c) {
		boolean isNotHex;
		isNotHex = Character.digit(c, 16) == -1;
		if (isNotHex) {
			return false;
		}
		return true;
	}

	/*Converts full IP address in HEX to decimal*/
	public static String hexIPtoIP(String hex){
		List<String> hexplode;
		String tempIp;
		String newIp;
		//Remove hex identifier and leading 0's (not significant)
		tempIp = hex.replace("0x","");
		tempIp = ltrim(tempIp);   
		//It might be hex
		if(isHex(tempIp)){
			//There may be a load of junk before the part we need
			if(tempIp.length()>8){
				tempIp = tempIp.substring(tempIp.length()-7);   
			}
			hexplode = Utils.preg_split("//", tempIp);
			while(hexplode.size()<8) {
				hexplode.add(0, "0");
			}
			//Normalise
			newIp = Integer.parseInt(hexplode.get(0)+hexplode.get(1),16)+"."+
					Integer.parseInt(hexplode.get(2)+hexplode.get(3),16)+"."+
					Integer.parseInt(hexplode.get(4)+hexplode.get(5),16)+"."+
					Integer.parseInt(hexplode.get(6)+hexplode.get(7),16);
			//Now check if its an IP
			if(is_ip(newIp))
				return newIp;
			else
				return null;
		}
		else
			return null;
	}

	/**
	 *  Equivalent to the PHP's function
	 **/
	public static int substr_count (String search, String text) {
		int count = text.split(search).length - 1;
		return count;
	}

	public static boolean isInt(String toTest) {
		Pattern p = Pattern.compile("(\\d)+");
		Matcher m = p.matcher(toTest);
		if (m.lookingAt() && m.start() == 0 && m.end() == (toTest.length()))
			return true;
		return false;
	}

	/**
	 * Converts IP address part in HEX to decimal
	 **/
	public static int iphexdec(String hex) {
		String temp;    
		//Removes any leading 0x (used to denote hex) and then and leading 0's)
		temp = hex.replace("0x", "");
		temp = ltrim(temp);       
		return Integer.parseInt(temp,16);
	}

	static String downloadFullHash(String url, List<GSBEntry> matchingPrefixes){
		if(matchingPrefixes.size()<1)
			return "";

		URL a_Url = null;
		byte[] body;
		StringBuilder bodyBuilder = new StringBuilder();
		int prefixsize = convertHexToASCII(matchingPrefixes.get(0).getPrefix()).length();
		for(GSBEntry matchingHostkey : matchingPrefixes){
			bodyBuilder.append(convertHexToASCII(matchingHostkey.getHostkey()));
		}
		int length = prefixsize*matchingPrefixes.size();
		bodyBuilder.append("\n");
		body = bodyBuilder.toString().getBytes();
		StringBuilder res = new StringBuilder();
		try{
			a_Url = new URL(url);
			HttpURLConnection urlConn = (HttpURLConnection) a_Url.openConnection();
			urlConn.setDoInput(true);
			urlConn.setDoOutput(true);
			DataOutputStream out = new DataOutputStream(urlConn.getOutputStream());
			out.writeBytes(prefixsize+":"+length+"\n");
			int tmp;
			for(int b=0; b< length; b++) {
				tmp = (int)(body[b] & 0xFF);
				out.writeByte(tmp);
			}
			out.close();

			//Reading the response
			InputStreamReader  response =  new InputStreamReader( urlConn.getInputStream(), "iso-8859-1");
			BufferedReader bufReader = new BufferedReader(response);
			String sLine;
			while ((sLine = bufReader.readLine()) != null){
				res.append(sLine+"\n");
			}
			urlConn.disconnect();		
		}
		catch(ConnectException ctx){
			//Connection lost : server may be down");
			ctx.printStackTrace();
		} catch (MalformedURLException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return res.toString();
	}

	/**
	 * Function downloads from URL's, POST data can be
	 * passed via options. $followbackoff indicates
	 * whether to follow backoff procedures or not
	 **/ 
	public static String googleDownloader(String url, String options, boolean followbackoff) {
		URL a_Url = null;
		StringBuilder res = new StringBuilder();
		try{
			a_Url = new URL(url);
			HttpURLConnection urlConn = (HttpURLConnection) a_Url.openConnection();
			urlConn.setDoInput(true);
			urlConn.setDoOutput(true);
			PrintStream pos = new PrintStream(urlConn.getOutputStream());
			pos.println(options);
			pos.close();
			InputStreamReader  response =  new InputStreamReader( urlConn.getInputStream(), "US-ASCII");
			BufferedReader bufReader = new BufferedReader(response);
			String sLine;

			while ((sLine = bufReader.readLine()) != null){
				res.append(sLine+"\n");
			}
			//			if(followbackoff && urlConn.getResponseCode()>299) {
			//				GSBWrapper.backoff(false, "data");
			//			}
			urlConn.disconnect();
		}
		catch(ConnectException ctx){
			//Connection lost : server may be down");
			ctx.printStackTrace();
		} catch (MalformedURLException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return res.toString();
	}           

	/**
	 * Function downloads from URL's, POST data can be
	 * passed via options. $followbackoff indicates
	 * whether to follow backoff procedures or not
	 **/ 
	public static List<Integer> googleDownloaderBytes(String url, String options) {
		URL a_Url = null;
		List<Integer> res = new ArrayList<Integer>();
		HttpURLConnection urlConn = null;
		try{
			a_Url = new URL(url);
			urlConn = (HttpURLConnection) a_Url.openConnection();
			urlConn.setDoInput(true);
			urlConn.setDoOutput(true);
			PrintStream pos = new PrintStream(urlConn.getOutputStream());
			pos.println(options);
			pos.close();
			//GSB Response "+urlConn.getResponseMessage());
			DataInputStream bufReader = new DataInputStream(urlConn.getInputStream());
			int value;
			while (true) {
				value = bufReader.readUnsignedByte();
				res.add(value);
			}
		} catch (EOFException e) {
			urlConn.disconnect();
		}
		catch(ConnectException ctx){
			//Connection lost : server may be down");
			ctx.printStackTrace();
		} catch (MalformedURLException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return res;
	}  


	private static char rawURLEncodeChar(char c) {
		String res = "";
		char[] arrayChar = new char[1];
		String s = new String(arrayChar);
		s = s.concat(String.valueOf(c));
		try {
			res = URLEncoder.encode(s,"UTF8");
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return res.charAt(0);
	}

	public static char percentCode2char(String s) {
		String res = "";
		try {
			res = URLDecoder.decode(s,"UTF8");
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return res.charAt(0);
	}

	/**
	 * Equivalent to the the PHP's implode function.
	 * @param objects
	 * @param delim
	 * @return Joined array elements 
	 */
	public static String implode(Object[] objects, String delim) {
		StringBuilder out = new StringBuilder();
		for(int i=0; i<objects.length; i++) {
			if(i!=0) {
				out.append(delim);
			}
			out.append((String)objects[i]);
		}
		return out.toString();
	}

	public static String bytes2Hex(byte[] bytes) {
		StringBuffer hexString = new StringBuffer();
		for (int i=0;i<bytes.length;i++) {
			hexString.append(Integer.toHexString(0xFF & bytes[i]));
		}
		return hexString.toString();
	}

	/** Returns the canonicalized form of a URL, core logic written by Henrik Sjostrand, heavily modified for v2 by Dave Shanley.
	 * @author Henrik Sjostrand, Netvouz, http://www.netvouz.com/, info@netvouz.com & Dave Shanley <dave@buildabrand.com>
	 * @param queryURL
	 * @return
	 * @throws GSBException
	 */
	public static String canonicalizeURL(String queryURL) throws GSBException, Exception{

		if (queryURL == null)
			return null;

		String url = queryURL;

		try {

			/* first of all extract the components of the URL to make sure that it has a protocol! */
			if(url.indexOf("http://") <=-1 && url.indexOf("https://")<=-1) url = "http://"+url;

			url = url.replaceAll("[\\t\\n\\r\\f\\e]*", ""); // replace all whitespace and escape characters.

			URL theURL = new URL(url);
			String host = theURL.getHost();
			String path = theURL.getPath();
			String query = theURL.getQuery();
			String protocol = theURL.getProtocol();
			if(protocol==null||protocol.isEmpty()) protocol = "http";
			int port = theURL.getPort();
			String user = theURL.getUserInfo();

			/* escape host */
			host = unescape(host);

			/* decode host / IP */
			host = decodeHost(host);


			/* escape non standard characters for host */
			StringBuffer sb = new StringBuffer();
			for (int i = 0; i < host.length(); i++) {
				char c = host.charAt(i);
				if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || c == '.' || c == '-')
					sb.append(c);
				else
					sb.append(codec.encode(String.valueOf(c))); // Escape using UTF-8
			}
			host = sb.toString();
			
			/* remove leading and trailing dots */
			while (host.startsWith("."))
				host = host.substring(1);
			while (host.endsWith("."))
				host = host.substring(0, host.length() - 1);

			/* replace consecutive dots with a single dot */
			int p = 0;
			while ((p = host.indexOf("..")) != -1)
				host = host.substring(0, p + 1) + host.substring(p + 2);

			/* add a trailing slash if the path is empty */
			if ("".equals(path))
				host = host + "/";

			/* find and replace any dodgy decoded escape characters */
			Pattern pattern =  Pattern.compile("([a-z]{1})([0-9]{2})");
			Matcher matcher = pattern.matcher(host);
			String val = "$2";
			while (matcher.find()) {
				host = matcher.replaceAll(val);
			}

			/* replace any encoded percentage signs */
			host = host.replaceAll("(?i)%5C", "%");

			/* unescape path to remove all hex encodings */
			path = unescape(path);

			/* remove double slashes from path  */
			while ((p = path.indexOf("//")) != -1)
				path = path.substring(0, p + 1) + path.substring(p + 2);

			/* remove /./ occurences from path */
			while ((p = path.indexOf("/./")) != -1)
				path = path.substring(0, p + 1) + path.substring(p + 3);

			/* resolve /../ occurences in path */
			while ((p = path.indexOf("/../")) != -1) {
				int previousSlash = path.lastIndexOf("/", p-1);
				// if (previousSlash == -1) previousSlash = 0; // If path begins with /../
				path = path.substring(0, previousSlash) + path.substring(p + 3);
				p = previousSlash;
			}

			/* use URI class to normalise the URL */
			URI uri = null;
			try {

				/* only normalise if the host doesn't contain some odd hex */
				if(!host.contains("%") && !host.matches("[\\s].*")) { 
					uri = new URI(protocol, user, host, -1, path, query, null);
				}

			} catch (URISyntaxException exp) {

				try {

					/* only normalise if the host doesn't contain some odd hex */
					if(!host.contains("%") && !host.matches(".*[\\s].*")) { 
						uri = new URI(protocol, user, unescape(host), -1, path, query, null);
					}

				} catch (URISyntaxException e) {

					// total fail, forget it.
				}
			}

			/* only use URI normalized URL if it's not a total failure */
			if(uri!=null && !uri.normalize().getPath().toString().trim().isEmpty()) {
				path = uri.normalize().getPath().toString();
			}  



			/* escape the path */
			path = escape(path);

			/* unescape the query */
			query = unescape(query);

			/* re-escape the query */
			query = escape(query);


			/* re-assemble the URL */
			sb.setLength(0);
			sb.append(protocol + ":");

			sb.append("//");
			if (user != null)
				sb.append(user + "@");

			if (port != -1) {

				/* remove slash from host */
				if(host.lastIndexOf("/",host.length())>8) {
					host = host.substring(0,host.length()-1);
				}
				sb.append(host);
				sb.append(":");
				sb.append(port);
			} else {
				sb.append(host);
			}

			/* make sure any hashes are re-encoded back to %23*/
			path = path.replaceAll("#","%23");

			sb.append(path);
			if(sb.toString().endsWith("//")) sb = sb.replace(sb.length()-1, sb.length(), "");

			if (query != null)
				sb.append("?" + query);

			url = sb.toString();
		} catch (Exception e) {
			e.printStackTrace();
			throw new GSBException("Could not canonicalise URL: " + queryURL);
		}
		return url;
	}

	/** Unscapes a string repeatedly to remove all escaped characters. Returns null if the string is invalid.
	 * @param url
	 * @return
	 * @throws GSBException
	 */
	private static String unescape(String url) throws GSBException {

		if (url == null)
			return null;

		StringBuffer text1 = new StringBuffer(url);
		url = text1.toString();

		String text2 = url;

		for(int x = 0; x < 50; x++) { // keep iterating to make sure all those encodings are killed.

			text2 = codec.decode(text2); // Unescape repeatedly until no more percent signs left
		}       
		return text2;
	}

	/** Escapes a string by replacing characters having ASCII <=32, >=127, or % with their UTF-8-escaped codes 
	 * 
	 * @param url
	 * @return escaped url
	 * @author Henrik Sjostrand, Netvouz, http://www.netvouz.com/, info@netvouz.com
	 */
	private static String escape(String url) throws GSBException {
		if (url == null)
			return null;
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < url.length(); i++) {
			char c = url.charAt(i);
			if (c == ' ')
				sb.append("%20");
			else if (c <= 32 || c >= 127 || c == '%') {
				sb.append(codec.encode(String.valueOf(c))); // replace crappy URLDecoder form v1 with something a little more useful.
			} else
				sb.append(c);
		}
		return sb.toString();
	}  

	/**
	 * Decode a host, If it is a hostname, return it, if it is an IP decode (encoding, including octal & hex)
	 * @param host
	 * @return
	 */
	private static String decodeHost(String host) {
		return host;
//		try {
//			InetAddress addr = InetAddress.getByName(host);
//			logger.debug("checking host for IP: "+  host);
//			if(host.matches(IPValidation)) return host.toLowerCase();
//
//
//			if(host.indexOf('.')>-1) { // most likely a domain 
//				logger.debug("host contains period");
//				return addr.getHostName().toLowerCase();
//
//			} else {
//
//				logger.debug("host does not contain a period");
//				if(!addr.getHostName().matches(IPValidation)) return addr.getHostAddress();
//				return addr.getHostName().toLowerCase();
//
//			}
//
//		} catch (UnknownHostException exp) {
//			return host;
//		}
	}

	/**
	 * Convert Hex in ASCII
	 * @param Hex value
	 * @return ASCII value
	 */
	private static String convertHexToASCII(String hex){
		StringBuilder sb = new StringBuilder();
		StringBuilder temp = new StringBuilder();
		for( int i=0; i<hex.length()-1; i+=2 ){
			//grab the hex in pairs
			String output = hex.substring(i, (i + 2));
			//convert hex to decimal
			int decimal = Integer.parseInt(output, 16);
			//convert the decimal to character
			sb.append((char)decimal);
			temp.append(decimal);
		}
		return sb.toString();
	}

	/**
	 * Convert ASCII to Hex
	 * @param ASCII value
	 * @return Hex value
	 */
	public static String convertASCIIToHex(String ascii){
		StringBuilder hex = new StringBuilder();
		for (int i=0; i < ascii.length(); i++) {
			hex.append(Integer.toHexString(ascii.charAt(i)));
		}      
		return hex.toString();
	}
}