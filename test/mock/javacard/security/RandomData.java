package javacard.security;

import java.util.Random;

public class RandomData {
	public static final RandomData getInstance(byte algorithm) {
		return new RandomData();
	}
	
	public void generateData(byte[] buffer, short offset, short length) {
		Random r = new Random();
		
		for(int i = 0; i < length; i++) {
			buffer[offset + i] = (byte) r.nextInt();
		}
	}
}
