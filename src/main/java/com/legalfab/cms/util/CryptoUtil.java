package com.legalfab.cms.util;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;


public class CryptoUtil {
	/**
     * @param args the command line arguments
     */
    static PublicKey pubKey;
    static PrivateKey privateKey;
    static Provider provider;
    static byte[] encrypted;
    static ECParameterSpec ecSpec;
    static String hexPriv;
    
    public static PublicKey getPublicKey() {
    	return pubKey;
    }
    
    public static PrivateKey getPrivateKey() {
    	return privateKey;
    }

    static {
        Security.addProvider(new BouncyCastleProvider());
//        provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
        //hexPriv = "ca35b7d915458ef540ade6068dfe2f44e8fa733c"; //"4197e4321201ecb3c3667b07fd62fb8731cef80ea3c0228a996034a552c9d3c";
        hexPriv = "920a42ebb7852c0747db7cebd437b45b51b0e12434f9b07561e480c1b465aefe";
    }

    public CryptoUtil() {
    }

    
    public static void initialize (String privKey) {
    	
    	generateKeysFromPrivateKey(privKey);
    }

    private static byte[] convert(byte[] msg, Key key, int mode) {
        try {
            Cipher cipher = Cipher.getInstance("ECIES", BouncyCastleProvider.PROVIDER_NAME);
            cipher.init(mode, key);
            return cipher.doFinal(msg);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(CryptoUtil.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(CryptoUtil.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(CryptoUtil.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(CryptoUtil.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CryptoUtil.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(CryptoUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    public static String encrypt(String plainText, String publicKey) {
    	
    	byte[] encMsg = encrypt(plainText.getBytes(), pubKey);
    	return DatatypeConverter.printHexBinary(encMsg);
    }
    
    public static String decrypt(String encText, String privKey) {
    	
    	byte[] plainMsg = decrypt(DatatypeConverter.parseHexBinary(encText), privateKey);
    	return new String(plainMsg);
    }

    public static byte[] encrypt(byte[] msg, Key key) {
        return convert(msg, key, Cipher.ENCRYPT_MODE);
    }

    public static byte[] decrypt(byte[] msg, Key key) {
        return convert(msg, key, Cipher.DECRYPT_MODE);
    }

    public static void generateNew(Provider provider) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", provider);
            System.out.println("kpg = " + kpg.getAlgorithm());
            ECGenParameterSpec ecgp = new ECGenParameterSpec("secp256k1");
            System.out.println("ecgp = " + ecgp.getName());
            kpg.initialize(256);
            KeyPair pair = kpg.generateKeyPair();
            pubKey = pair.getPublic();
            privateKey = pair.getPrivate();
            print();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CryptoUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public static void print() {
        System.out.println("pubKey.toString() = " +  pubKey);
        System.out.println("privateKey.toString() = " + privateKey);
    }

    public static void generateKeysFromPrivateKey(String privKey) {
        try {
            KeyFactory factory = KeyFactory.getInstance("EC");

            ECPrivateKeySpec privSpec = new ECPrivateKeySpec(new BigInteger(privKey,16), ecSpec);
            privateKey = factory.generatePrivate(privSpec);
            
            //ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(new BigInteger(privKey,16), ecSpec);

            ECPublicKeySpec pubSpec = new ECPublicKeySpec(privSpec.getParams().getG().multiply(privSpec.getD()), ecSpec);
            pubKey = factory.generatePublic(pubSpec);
            
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(CryptoUtil.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CryptoUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public static PublicKey getPublicKey(String pubKeyStr) throws SignatureException {
    	
        X9ECParameters curve = SECNamedCurves.getByName("secp256r1");
        ECPoint point = curve.getCurve().decodePoint(Hex.decode(pubKeyStr));

        try {
			return KeyFactory.getInstance("ECDSA").generatePublic(new ECPublicKeySpec(point,ecSpec));
		} catch (GeneralSecurityException ex) {
			throw new SignatureException(ex);
		}
    }
    
    public static PrivateKey getPrivateKey(String privateKeyStr) {
    	
    	PrivateKey prKey = null;
    	
	    try {
	    	KeyFactory factory = KeyFactory.getInstance("EC");
	        ECPrivateKeySpec privSpec = new ECPrivateKeySpec(new BigInteger(privateKeyStr,16), ecSpec);
	        prKey = factory.generatePrivate(privSpec);
	    	
	    } catch (InvalidKeySpecException ex) {
	        Logger.getLogger(CryptoUtil.class.getName()).log(Level.SEVERE, null, ex);
	    } catch (NoSuchAlgorithmException ex) {
	        Logger.getLogger(CryptoUtil.class.getName()).log(Level.SEVERE, null, ex);
	    }
	    
	    return prKey;
    }

    public static void test() {
        String msg = "accesscode_encryption";
        System.out.println("original msg = " + msg + "\n");

        byte[] encryptedBytes = encrypt(msg.getBytes(), pubKey);
        System.out.print("encrypted bytes = [");
        for (byte token : encryptedBytes) {
            System.out.print(token);
        }
        System.out.print("]");
        System.out.println("\n");
        encrypted = encryptedBytes;

        byte[] decryptedBytes = decrypt(encryptedBytes, privateKey);
        StringBuilder decryptedMsg = new StringBuilder();
        for (byte token : decryptedBytes) {
            decryptedMsg.append((char) token);
        }
        System.out.println("decrypted msg = " + decryptedMsg.toString());
    }

    public static void test2(byte[] encryptedBytes) {
        byte[] decryptedBytes = decrypt(encryptedBytes, privateKey);
        StringBuilder decryptedMsg = new StringBuilder();
        for (byte token : decryptedBytes) {
            decryptedMsg.append((char) token);
        }
        System.out.println("decrypted msg test2 === " + decryptedMsg.toString());
    }
    
    public static String sign(String data, String prKey) {
    	
    	byte[] signature = null;
    	
    	try {
    	
	    	Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");
	    	ecdsaSign.initSign(getPrivateKey());
	    	ecdsaSign.update(data.getBytes("UTF-8"));
	    	signature = ecdsaSign.sign();
    	
    	} catch (Exception e) {
    		e.printStackTrace();
    	}
    	
    	return DatatypeConverter.printHexBinary(signature);
    }
    
    public static boolean verify(String data, String signatureHex, String pbKey) {
    	
    	byte[] signature = DatatypeConverter.parseHexBinary(signatureHex);
    	boolean result = false;
    	
    	try {
        	
    	Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", "BC");
    	ecdsaVerify.initVerify(getPublicKey());
    	ecdsaVerify.update(data.getBytes("UTF-8"));
    	result = ecdsaVerify.verify(signature);
    	} catch (Exception e) {
    		e.printStackTrace();
    	}
    	
    	return result;
    }
    
    public static String getSHA256Hash(String data) {
    	
    	try {
    	MessageDigest digest = MessageDigest.getInstance("SHA-256");
    	byte[] hash = digest.digest(data.getBytes(StandardCharsets.UTF_8));
    	
    	return DatatypeConverter.printHexBinary(hash);
    	}catch (Exception e) {
			// TODO: handle exception
		}
    	
    	return null;
    }
    
}
