package com.gsbanalyzer.util;

import java.net.MalformedURLException;
import java.net.URL;

public class Converter {
	
	/**
	 * Transform an URL to a Domain
	 * @param url (www.website.com/page)
	 * @return domain (website.com)
	 */
	public static String URL2Domain(String url) {
		String domain = "";
		if(!url.startsWith("http://")) {
			url = "http://".concat(url);
		}
		try {
			URL uri = new URL(url);
			domain = uri.getHost();
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}
		return domain;
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
