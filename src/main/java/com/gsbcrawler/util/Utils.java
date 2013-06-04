package com.gsbcrawler.util;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class Utils {

	/**
	 * Equivalent to the PHP function
	 * @param pattern
	 * @param subject
	 * @return a list of splitted string
	 */
	public static List<String> preg_split(String pattern, String subject){
		List<String> res = new ArrayList<String>();
		String[] splittedResult = subject.split(pattern);
		for(String string : splittedResult) {
			if(string.length()>0) {
				res.add(string);
			}
		}
		return res;
	}

	/**
	 * Merged all Strings of a Map
	 * @param map
	 * @param delim
	 * @return merged String
	 */
	public static String implodeMap(HashMap<String, String> map,String delim) {
		StringBuilder out = new StringBuilder();
		int i = 0;
		for(java.util.Map.Entry<String, String> entry : map.entrySet()) {
			if(i!=0) {
				out.append(delim);
			}
			out.append(entry.getValue());
		}
		return out.toString();
	}

	/**
	 * Merged a list of Strings 
	 * @param list of String
	 * @return the merged list in a String
	 */
	public static String list2String(List<String> list) {
		StringBuilder sb = new StringBuilder();
		for(String s : list) {
			sb.append(s);
		}
		return sb.toString();
	}

	public static String implodeList(List<List<String>> prefixes, String delim) {
		StringBuilder res = new StringBuilder();
		int i = 0;
		for(List<String> list : prefixes) {
			for(String s : list) {
				if(i!=0) {
					res.append(delim);
				}
				res.append(s);
			}
		}
		return res.toString();
	}

	public static String implodeMap(Map<String, Map<String, String>> map, String delim) {
		StringBuilder res = new StringBuilder();
		int i = 0;
		for (Iterator<Map<String, String>> it1 = map.values().iterator() ; it1.hasNext() ;){
			for (Iterator<String> it2 = it1.next().values().iterator() ; it2.hasNext() ;){
				if(i!=0) {
					res.append(delim);
				}
				res.append(it2.next());
			}
		}
		return res.toString();
	}

	/**
	 * Splits the list around matches of the character
	 * @param list
	 * @param c (example '\n')
	 * @return a list of splitted list
	 */
	public static List<List<Integer>> splitList(List<Integer> list, char c, int limit){
		List<List<Integer>> res = new ArrayList<List<Integer>>();
		int fromIndex = 0;
		int nbList = 1;
		boolean finish = false;
		for(int toIndex=0;toIndex<list.size();toIndex++) {
			if(list.get(toIndex) == c) {
				if(nbList<limit) {
					res.add(list.subList(fromIndex, toIndex));
					fromIndex = toIndex+1;
					nbList++;
				}
				else {
					res.add(list.subList(fromIndex, list.size()));
					finish = true;
					break;
				}

			}
		}
		if(!finish) {
			res.add(list.subList(fromIndex, list.size()));
		}
		return res;
	}

	/**
	 * Convert a list of Integer into a String 
	 * @param list list of integer
	 * @return a String representation
	 */
	public static String listInt2String(List<Integer> list) {
		StringBuilder res = new StringBuilder();
		for(Integer i : list) {
			res.append(Character.toChars(i));
		}
		return res.toString();
	}

	public static String MapString2String(Map<String,String> map) {
		StringBuilder res = new StringBuilder();
		for (Map.Entry<String,String> e : map.entrySet()){
			res.append(e.getValue());
		}
		return res.toString();
	}

	/**
	 * Convert a list of integer into an hexadecimal String
	 * @param list a List of Integer
	 * @param begin first element
	 * @param end last element
	 * @return an hexadecimal representation
	 */
	public static String getHexFromUnsignedByteList(List<Integer> list, int begin, int end) {
		StringBuilder res = new StringBuilder();
		for(int i : list.subList(begin, end)){
			res.append(Integer.toHexString(i));
		}
		return res.toString();
	}

	/**
	 * Convert an integer (contained into a list)  into an hexadecimal String
	 * @param list a List of Integer
	 * @param index
	 * @return an hexadecimal representation
	 */
	public static String getHexFromUnsignedByteList(List<Integer> list, int index) {
		StringBuilder res = new StringBuilder();
		res.append(Integer.toHexString(list.get(index)));
		return res.toString();
	}

	/**
	 * Read a SQL File's stream
	 * @param inputStream
	 * @return a list of string. Each string is a line of the SQL File
	 */
	public static List<String> readSQLFile(InputStream inputStream) {
		List<String> res = new ArrayList<String>();
		StringBuilder sb = new StringBuilder();
		BufferedReader bufferedReader = null;
		String ligne;
		try{
			bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
			while ((ligne = bufferedReader.readLine()) != null) {
				sb.append(ligne+"\n");
				if(ligne.endsWith(";")){
					res.add(sb.toString());
					sb = new StringBuilder();
				}
			}
		}
		catch(FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		finally {
			try {
				bufferedReader.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return res;
	}

	/**
	 * Equivalent to the the PHP's implode function.
	 * @param objects
	 * @param delim
	 * @return Joined array elements 
	 */
	public static String implodeOneChar(char[] urlcharsarray, String delim) {
		StringBuilder out = new StringBuilder();
		for(int i=0; i<urlcharsarray.length; i++) {
			if(i!=0) {
				out.append(delim);
			}
			if(urlcharsarray[i] != ' ') out.append(urlcharsarray[i]);
		}
		return out.toString();
	}

	public static String implodeListMap(ArrayList<Map<String, String>> map, String delim) {
		StringBuilder res = new StringBuilder();
		int i = 0;
		for (Iterator<Map<String, String>> it1 = map.iterator() ; it1.hasNext() ;){
			for (Iterator<String> it2 = it1.next().values().iterator() ; it2.hasNext() ;){
				if(i!=0) {
					res.append(delim);
				}
				res.append(it2.next());
			}
		}
		return res.toString();
	}

	public static boolean checkIp (String sip) {
		String [] parts = sip.split ("\\.");
		for (String s : parts) {
			if(!isNumeric(s)) return false;
			long i = Long.parseLong(s);
			if (i < 0 || i > 255) {
				return false;
			}
		}
		return true;
	} 
	
	public static boolean isNumeric(String str){
	  return str.matches("-?\\d+(\\.\\d+)?");
	}
	
	/**
	 * Transform an URL to a Domain
	 * @param url (www.website.com/page)
	 * @return domain (website.com)
	 */
	public static String URL2Domain(String url) {
		String address;
		String res = "";
		url = url.replaceAll("/{3,}", "//"); //if we found over three consecutive slashs, we replace by two
		String[] split = url.split("/");
		if(split.length>1) address = split[2];
		else address = split[0];
		split = address.split("\\.");
		if(split.length<2) return "";
		if(checkIp(split[split.length-2])) return "";
		res = split[split.length-2].concat(".").concat(split[split.length-1]);
		return res;
	}
	
	/**
	 * Delete all doubles quotes
	 */
	public static String[] deleteDoubleQuotes(String[] param) {
		for(int i=0;i<param.length;i++) {
			param[i] = param[i].replace("\"", "");
		}
		return param;	
	}
	

}