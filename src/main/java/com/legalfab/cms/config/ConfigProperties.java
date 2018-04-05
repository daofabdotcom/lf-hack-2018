package com.legalfab.cms.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Component;

@PropertySource("classpath:config.properties")
@Component
@ConfigurationProperties
public class ConfigProperties {
	
	private String storjServiceAccId;
	private String storjServiceAccKey;
	private String storjServiceAccNemonicLen;
	private String storjKeyFilePass;
	private String storjAuthParentDir;
	
	public String getStorjServiceAccId() {
		return storjServiceAccId;
	}
	public void setStorjServiceAccId(String storjServiceAccId) {
		this.storjServiceAccId = storjServiceAccId;
	}
	public String getStorjServiceAccKey() {
		return storjServiceAccKey;
	}
	public void setStorjServiceAccKey(String storjServiceAccKey) {
		this.storjServiceAccKey = storjServiceAccKey;
	}
	public String getStorjServiceAccNemonicLen() {
		return storjServiceAccNemonicLen;
	}
	public void setStorjServiceAccNemonicLen(String storjServiceAccNemonicLen) {
		this.storjServiceAccNemonicLen = storjServiceAccNemonicLen;
	}
	public String getStorjKeyFilePass() {
		return storjKeyFilePass;
	}
	public void setStorjKeyFilePass(String storjKeyFilePass) {
		this.storjKeyFilePass = storjKeyFilePass;
	}
	public String getStorjAuthParentDir() {
		return storjAuthParentDir;
	}
	public void setStorjAuthParentDir(String storjAuthParentDir) {
		this.storjAuthParentDir = storjAuthParentDir;
	}
	
	
}
