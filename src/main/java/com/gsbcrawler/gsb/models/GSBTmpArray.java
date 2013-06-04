package com.gsbcrawler.gsb.models;

import java.util.ArrayList;
import java.util.List;

public class GSBTmpArray {

	public String hostKey;
	public String count;
	public List<GSBPairs> pairs;
	
	public GSBTmpArray() {}
	
	public GSBTmpArray(String hostKey, String count) {
		super();
		this.hostKey = hostKey;
		this.count = count;
		this.pairs = new ArrayList<GSBPairs>();
	}

	public GSBTmpArray(String hostKey, String count, List<GSBPairs> pairs) {
		super();
		this.hostKey = hostKey;
		this.count = count;
		this.pairs = pairs;
	}

	public String getHostKey() {
		return hostKey;
	}
	
	public void setHostKey(String hostKey) {
		this.hostKey = hostKey;
	}
	
	public String getCount() {
		return count;
	}
	
	public void setCount(String count) {
		this.count = count;
	}
	
	public List<GSBPairs> getPairs() {
		return pairs;
	}

	public void setPairs(List<GSBPairs> pairs) {
		this.pairs = pairs;
	}

	@Override
	public String toString() {
		String res;
		res = "TmpArray [hostKey=" + hostKey + ", count=" + count + ", pairs=";
		for(GSBPairs p : pairs) {
			res = res.concat(p.toString());
		}
		return res;
	}		
}