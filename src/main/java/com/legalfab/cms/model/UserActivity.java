package com.legalfab.cms.model;

import java.util.Calendar;

public class UserActivity {

	private Long id; 
	private String senderAddress;
	private String receiverAddress;
	private Long receiverId;
	private Calendar logTime;
	private String transactionAddress;
	
	public String getSenderAddress() {
		return senderAddress;
	}
	public void setSenderAddress(String senderAddress) {
		this.senderAddress = senderAddress;
	}
	public String getReceiverAddress() {
		return receiverAddress;
	}
	public void setReceiverAddress(String receiverAddress) {
		this.receiverAddress = receiverAddress;
	}
	public Long getReceiverId() {
		return receiverId;
	}
	public void setReceiverId(Long receiverId) {
		this.receiverId = receiverId;
	}
	public Calendar getLogTime() {
		return logTime;
	}
	public void setLogTime(Calendar logTime) {
		this.logTime = logTime;
	}
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
	}
	public String getTransactionAddress() {
		return transactionAddress;
	}
	public void setTransactionAddress(String transactionAddress) {
		this.transactionAddress = transactionAddress;
	}
	
}
