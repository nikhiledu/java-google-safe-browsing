package com.gsbcrawler.gsb;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import com.gsbcrawler.GSBCrawler;


public class GSBURLUtil {
	
	/**
	 * Equivalent to the the PHP's implode function.
	 * @param objects
	 * @param delim
	 * @return Joined array elements 
	 */
	public static String implode(Object[] objects, String delim) {
		//INSERT INTO "googpub-phish-shavar_add_index" (ChunkNum,Chunklen) VALUES "(233044,310)";
		
		
		//INSERT INTO "googpub-phish-shavar_add_index" (ChunkNum,Chunklen) VALUES "(233071,131)";
		//org.postgresql.util.PSQLException: ERROR: syntax error at or near ""(233071,131)""
		StringBuilder out = new StringBuilder();
		for(int i=0; i<objects.length; i++) {
			if(i!=0) {
				out.append(delim);
			}
			
			out.append((String)(objects[i]));		
		}
		return out.toString();
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
			//Connection lost : server may be down
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
			//Connection lost : server may be down
			ctx.printStackTrace();
		} catch (MalformedURLException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		finally{
			//Chunk received
		}
		return res;
	}  
	
	/**
	 *  Equivalent to the PHP's function
	 **/
	public static int substr_count (String search, String text) {
		int count = text.split(search).length - 1;
		return count;
	}
}
