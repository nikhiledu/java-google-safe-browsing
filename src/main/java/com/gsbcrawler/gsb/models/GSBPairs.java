package com.gsbcrawler.gsb.models;

public class GSBPairs {

	private String prefix;
	private int addChunkNum;
	
	public GSBPairs(String prefix) {
		super();
		this.prefix = prefix;
	}

	public GSBPairs(String prefix, int addChunkNum) {
		super();
		this.prefix = prefix;
		this.addChunkNum = addChunkNum;
	}

	public String getPrefix() {
		return prefix;
	}

	public void setPrefix(String prefix) {
		this.prefix = prefix;
	}

	public int getAddChunkNum() {
		return addChunkNum;
	}

	public void setAddChunkNum(int addChunkNum) {
		this.addChunkNum = addChunkNum;
	}

	@Override
	public String toString() {
		return "Pairs [prefix=" + prefix + ", addChunkNum=" + addChunkNum + "]";
	}
}
