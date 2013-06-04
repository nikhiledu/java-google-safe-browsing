package com.gsbcrawler.gsb.models;

public class GSBUrlParts {

	private String Host;
	private String path;
	private String query;
	private boolean usingIP;
	
	public GSBUrlParts(String host, String path, String query, boolean usingip) {
		Host = host;
		this.path = path;
		this.query = query;
		usingIP = usingip;
	}

	public String getHost() {
		return Host;
	}

	public void setHost(String host) {
		Host = host;
	}

	public String getPath() {
		return path;
	}

	public void setPath(String path) {
		this.path = path;
	}

	public String getQuery() {
		return query;
	}

	public void setQuery(String query) {
		this.query = query;
	}

	public boolean getusingIP() {
		return usingIP;
	}

	public void setusingIP(boolean iP) {
		usingIP = iP;
	}

	@Override
	public String toString() {
		return "GSBUrlParts [Host=" + Host + ", path=" + path + ", query="
				+ query + ", usingIP=" + usingIP + "]";
	}
}