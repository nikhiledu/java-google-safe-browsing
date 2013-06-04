package com.gsbanalyzer.gsb.models;
/**
 * An infected URL found by GSB
 * @author Julien SOSIN
 * jsosin@domaintools.com
 */
public class GSBInfectedUrl {

	private String domain;
	private String type; //phishing or malware
	private Boolean verified;
	
	public GSBInfectedUrl(String domain, String type, Boolean reliability) {
		super();
		this.domain = domain;
		this.type = type;
		this.verified = reliability;
	}

	public String getDomain() {
		return domain;
	}

	public void setUrl(String domain) {
		this.domain = domain;
	}

	/**
	 * Type of infection
	 * @return phishing or malware
	 */
	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	/**
	 * @return true if the domain is still on GSB's lists, false if it is only in your DB
	 */
	public Boolean isVerified() {
		return verified;
	}

	public void setVerified(Boolean verified) {
		this.verified = verified;
	}

	@Override
	public String toString() {
		return "GSBInfectedUrl [domain=" + domain + ", type=" + type
				+ ", verified=" + verified + "]";
	}
}