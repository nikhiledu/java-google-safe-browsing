package com.gsbcrawler.gsb.models;

import java.util.ArrayList;

public class GSBArray {

	private int chunkNum;
	private int hashLen;
	private int chunkLen;
	private ArrayList<GSBTmpArray> real;
	
	public GSBArray(int hashLen, int chunkLen, ArrayList<GSBTmpArray> real) {
		this.hashLen = hashLen;
		this.chunkLen = chunkLen;
		this.real = real;
	}
	
	public GSBArray(int chunkNum, int hashLen, int chunkLen, ArrayList<GSBTmpArray> real) {
		this.chunkNum = chunkNum;
		this.hashLen = hashLen;
		this.chunkLen = chunkLen;
		this.real = real;
	}

	public GSBArray(int chunkNum, int hashLen, int chunkLen) {
		this.chunkNum = chunkNum;
		this.hashLen = hashLen;
		this.chunkLen = chunkLen;
	}

	public int getChunkNum() {
		return chunkNum;
	}

	public void setChunkNum(int chunkNum) {
		this.chunkNum = chunkNum;
	}
	
	public int getHashLen() {
		return hashLen;
	}
	public void setHashLen(int hashLen) {
		this.hashLen = hashLen;
	}
	public int getChunkLen() {
		return chunkLen;
	}
	public void setChunkLen(int chunkLen) {
		this.chunkLen = chunkLen;
	}
	public ArrayList<GSBTmpArray> getReal() {
		return real;
	}
	public void setReal(ArrayList<GSBTmpArray> real) {
		this.real = real;
	}

	@Override
	public String toString() {
		String res = "GSBArray [chunkNum=" + chunkNum + ", hashLen=" + hashLen
				+ ", chunkLen=" + chunkLen + ", real=";
		for(GSBTmpArray ta : real) {
			res = res.concat(ta.toString());
		}
		res = res.concat( "]");
		return res;
	}
	
	
}
