package javacard.security;

import java.security.DigestException;
import java.security.NoSuchAlgorithmException;

public class MessageDigest {
	
	private java.security.MessageDigest sha1;
	
    public static final MessageDigest getInstance(byte algorithm, boolean externalAccess) {
    	return new MessageDigest();
    }
    
    public MessageDigest() {
    	try {
			sha1 = java.security.MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}


	public void reset() {
    	sha1.reset();
    }
    
    public void update(byte[] inBuff, short inOffset, short inLength) {
    	sha1.update(inBuff, inOffset, inLength);
    }
    
    public short doFinal(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) {
    	sha1.update(inBuff, inOffset, inLength);
    	try {
			return (short) sha1.digest(outBuff, outOffset, 20);
		} catch (DigestException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	return 0;
    }
}
