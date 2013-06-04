package com.gsbcrawler.gsb.models;

public enum GSBModeEnum {

	GSB_ADD(0,"add"),
	GSB_SUB(1,"sub");
	
	private final int id;
	private final String name;
	
	private GSBModeEnum(int id, String name) {
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
