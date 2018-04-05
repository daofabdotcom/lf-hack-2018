package com.legalfab.cms.controller;

import java.util.HashMap;
import java.util.Map;

import org.json.JSONException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.legalfab.cms.model.Crypto;
import com.legalfab.cms.model.UserActivity;
import com.legalfab.cms.service.ActivityService;
import com.legalfab.cms.util.CryptoUtil;

@RestController
@RequestMapping("/activity")
public class ActivityController {

	@Autowired
	private ActivityService service;

	@GetMapping("/dataSent")
	public Object constructDataSent(@RequestBody Crypto crypto) {
		
		String encData = service.encryptUsingPublicKey(crypto.getData(), crypto.getReceiverKey());
		
		String hash = CryptoUtil.getSHA256Hash(crypto.getData());
		
		String signature = service.sign(hash, crypto.getSenderKey());
		
		Map<String, Object> responseMap = new HashMap<>();
		responseMap.put("status", "success");
		responseMap.put("encData", encData);
		responseMap.put("signature", signature);

		return new ResponseEntity<Object>(responseMap, HttpStatus.OK);
	}
	
	@GetMapping("/dataReturned")
	public Object constructDataReturned(@RequestBody Crypto crypto) {
		
		String plainData = service.decryptUsingPrivateKey(crypto.getData(), crypto.getSenderKey());
		
		boolean verifySuccess = service.verify(plainData, crypto.getSignature(), crypto.getReceiverKey());
		
		Map<String, Object> responseMap = new HashMap<>();
		responseMap.put("status", verifySuccess ? "success" : "failure");
		

		return new ResponseEntity<Object>(responseMap, HttpStatus.OK);
	}
	
	@PostMapping
	public Object createRequest(@RequestBody UserActivity userActivity) throws JSONException {

		service.saveActivity(userActivity);
		
		Map<String, Object> responseMap = new HashMap<>();
		responseMap.put("status", "success");
		
		return new ResponseEntity<Object>(responseMap, HttpStatus.OK);
	}

	
	
}
