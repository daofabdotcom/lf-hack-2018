package com.legalfab.cms.model;

public class Crypto {
	
	private String data;
	private String signature;
	private String senderKey;
	private String receiverKey;
	
	public String getData() {
		return data;
	}
	public void setData(String data) {
		this.data = data;
	}
	public String getSenderKey() {
		return senderKey;
	}
	public void setSenderKey(String senderKey) {
		this.senderKey = senderKey;
	}
	public String getReceiverKey() {
		return receiverKey;
	}
	public void setReceiverKey(String receiverKey) {
		this.receiverKey = receiverKey;
	}
	public String getSignature() {
		return signature;
	}
	public void setSignature(String signature) {
		this.signature = signature;
	}
	
	
}
