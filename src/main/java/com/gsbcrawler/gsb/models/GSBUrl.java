package com.gsbcrawler.gsb.models;


public class GSBUrl {

	private String GSBUrl;
	private String CleanURL;
	private GSBUrlParts Parts;
	
	public GSBUrl(String gSBUrl, String cleanURL, GSBUrlParts parts) {
		GSBUrl = gSBUrl;
		CleanURL = cleanURL;
		Parts = parts;
	}

	public String getGSBUrl() {
		return GSBUrl;
	}

	public void setGSBUrl(String gSBUrl) {
		GSBUrl = gSBUrl;
	}

	public String getCleanURL() {
		return CleanURL;
	}

	public void setCleanURL(String cleanURL) {
		CleanURL = cleanURL;
	}

	public GSBUrlParts getParts() {
		return Parts;
	}

	public void setParts(GSBUrlParts parts) {
		Parts = parts;
	}

	@Override
	public String toString() {
		return "GSBUrl [GSBUrl=" + GSBUrl + ", CleanURL=" + CleanURL
				+ ", Parts=" + Parts + "]";
	}
}