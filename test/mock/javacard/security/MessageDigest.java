package javacard.security;

/*
 * Copyright (c) 2013 Yubico AB
 * All rights reserved.
 */

import java.security.DigestException;
import java.security.NoSuchAlgorithmException;

public class MessageDigest {
	
	private java.security.MessageDigest digest;
	
    public static final byte ALG_SHA = 1;
    public static final byte ALG_SHA_256 = 4;

	
    public static final MessageDigest getInstance(byte algorithm, boolean externalAccess) {
    	return new MessageDigest(algorithm);
    }
    
    public MessageDigest(byte algorithm) {
    	try {
    		if(algorithm == ALG_SHA) {
    			digest = java.security.MessageDigest.getInstance("SHA-1");
    		} else if(algorithm == ALG_SHA_256) {
    			digest = java.security.MessageDigest.getInstance("SHA-256");
    		} else {
    			throw new NoSuchAlgorithmException("only support for sha-1 and sha-256.");
    		}
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}


	public void reset() {
    	digest.reset();
    }
    
    public void update(byte[] inBuff, short inOffset, short inLength) {
    	digest.update(inBuff, inOffset, inLength);
    }
    
    public short doFinal(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) {
    	digest.update(inBuff, inOffset, inLength);
    	try {
			return (short) digest.digest(outBuff, outOffset, digest.getDigestLength());
		} catch (DigestException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	return 0;
    }
}
