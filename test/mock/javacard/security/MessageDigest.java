package javacard.security;

/*
 * Copyright (c) 2013 Yubico AB
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
    
    public byte getLength() {
    	return (byte) digest.getDigestLength();
    }
}
