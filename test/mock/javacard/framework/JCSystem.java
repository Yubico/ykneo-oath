package javacard.framework;

/*
 * Copyright (c) 2013 Yubico AB
 * All rights reserved.
 */

public class JCSystem {
	public static byte[] makeTransientByteArray(short length, byte event) {
		return new byte[length];
	}
}
