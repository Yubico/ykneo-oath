package javacard.framework;

/*
 * Copyright (c) 2013 Yubico AB
 * All rights reserved.
 */

public class ISOException extends Exception {
	private static final long serialVersionUID = 1L;

	public ISOException(String message) {
    	super(message);
	}

	public static void throwIt(short sw) throws ISOException {
		String message = String.format("%x", sw);
    	throw new ISOException(message);
    }
}
