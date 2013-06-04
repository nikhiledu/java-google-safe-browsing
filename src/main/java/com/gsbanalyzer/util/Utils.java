package com.gsbanalyzer.util;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
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

	public static String readFile(String file) {
		StringBuilder res = new StringBuilder();
		BufferedReader bufferedReader = null;
		String ligne;
		try{
			bufferedReader = new BufferedReader(new FileReader(file));
			while ((ligne = bufferedReader.readLine()) != null) {
				res.append(ligne);
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
		return res.toString();
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
}
