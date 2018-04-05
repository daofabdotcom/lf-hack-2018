package com.legalfab.cms.service;

import javax.xml.bind.DatatypeConverter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.legalfab.cms.db.ActivityDB;
import com.legalfab.cms.model.UserActivity;
import com.legalfab.cms.util.CryptoUtil;

@Service
public class ActivityService {
	
	@Autowired
	ActivityDB activityDB;

	private static final long DEFAULT_USERID = 1l;
	private static final String fileHash = "9fbe5174561049bed643f3a4aad77c10157d8029fe06f82ab4098b87e2cc9c39";
	private static final String text = "G4768017";
	
	private static final String hexPriv = "920a42ebb7852c0747db7cebd437b45b51b0e12434f9b07561e480c1b465aefe";
	
	private static final String hexPublic = "3056301006072A8648CE3D020106052B8104000A034200045A87052AA357626FD8959D67846487C77E5E0510D2096E590334E5EE1F76E5872401D464E0036B2291079C8D28D64C6937F49A6B7C7CA964FCDBAA6620A2E030";
	
	
	public static String sign(String data, String privKey) {
		
		return CryptoUtil.sign(data, hexPriv);
	}
	
	public static boolean verify(String data, String signature, String pubKey) {
		
		return CryptoUtil.verify(data, signature, hexPublic);
	}
	
	public static String encryptUsingPublicKey(String data, String pubKey) {
		
		CryptoUtil.initialize(hexPriv);
		byte[] encArray = CryptoUtil.encrypt(data.getBytes(),CryptoUtil.getPublicKey());
		String hex = DatatypeConverter.printHexBinary(encArray);

		return hex;
	}
	
	public static String decryptUsingPrivateKey(String data, String privKey) {
		
		CryptoUtil.initialize(hexPriv);
		byte[] encArray = CryptoUtil.decrypt(DatatypeConverter.parseHexBinary(data),CryptoUtil.getPrivateKey());
		
		return new String(encArray);
	}
	
	public void saveActivity(UserActivity activity) {
		
		activityDB.save(activity);
		
	}
	
}
