package com.gsbanalyzer.gsb.models;

import com.gsbanalyzer.GSBAnalyzer;


public enum GSBListEnum {

	GSB_PHISHING_LIST(0,GSBAnalyzer.gsbPhishingList,GSBAnalyzer.RESULT_PHISHING),
	GSB_MALWARE_LIST(1,GSBAnalyzer.gsbMalwareList,GSBAnalyzer.RESULT_MALWARE);
	
	private final int id;
	private final String name;
	private final String type;
	
	private GSBListEnum(int id, String name, String type) {
		this.id = id;
		this.name = name;
		this.type = type;
	}

	public int getId() {
		return id;
	}

	public String getName() {
		return name;
	}

	public String getType() {
		return type;
	}
}
