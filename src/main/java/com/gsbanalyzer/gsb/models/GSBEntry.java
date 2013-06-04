package com.gsbanalyzer.gsb.models;

import java.util.HashMap;

/**
 * The PHP Wrapper of GSB use this strange structure. So i make an alias
 * @author Julien SOSIN
 *
 */
public class GSBEntry {

	private String domain;
	private String hostkey;
	private String prefix;
	private String fullhash;
		
	public GSBEntry() {}
	
	public GSBEntry(String domain, String prefix, String fullhash) {
		super();
		this.domain = domain;
		this.prefix = prefix;
		this.fullhash = fullhash;
	}

	public String getDomain() {
		return domain;
	}

	public void setDomain(String domain) {
		this.domain = domain;
	}

	public String getPrefix() {
		return prefix;
	}

	public void setPrefix(String prefix) {
		this.prefix = prefix;
	}

	public void setFullhash(String fullhash) {
		this.fullhash = fullhash;
	}

	public String getFullhash() {
		return this.fullhash;
	}

	public String getHostkey() {
		return hostkey;
	}

	public void setHostkey(String hostkey) {
		this.hostkey = hostkey;
	}

	@Override
	public String toString() {
		return "GSBEntry [host=" + domain + ", prefix=" + prefix + ", fullhash="
				+ fullhash + "]";
	}
}