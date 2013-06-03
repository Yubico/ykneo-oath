package pkgYkneoOathTest;

/*
 * Copyright (c) 2013 Yubico AB
 * All rights reserved.
 */

import javacard.framework.APDU;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;


import pkgYkneoOath.OathObj;
import pkgYkneoOath.YkneoOath;

public class YkneoOathTest {
	YkneoOath ykneoOath;
	
	APDU listApdu;
	
	@After
	public void tearDown() {
		OathObj.firstObject = null;
		OathObj.lastObject = null;
	}
	
	@Before
	public void setup() {
		ykneoOath = new YkneoOath();
		byte[] list = new byte[256];
		list[1] = (byte) 0xa1;
		listApdu = new APDU(list);
	}
	
	@Test
	public void testEmptyList() {
		assertNull(OathObj.firstObject);
		ykneoOath.process(listApdu);
		byte[] buf = listApdu.getBuffer();
		assertEquals((byte)0xa1, buf[0]);
		assertEquals(0, buf[1]);
	}
	
	@Test
	public void testLife() {
		APDU putApdu = new APDU(new byte[] {
				0x00, 0x01, 0x00, 0x00, 0x1c,
				0x7a, 0x04, 'k', 'a', 'k', 'a',
				0x7b, 0x01, 0x14, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
		});
		assertNull(OathObj.firstObject);
		ykneoOath.process(putApdu);
		assertNotNull(OathObj.firstObject);
		ykneoOath.process(listApdu);
		byte[] expect = new byte[256];
		System.arraycopy(new byte[] {(byte) 0xa1, 6, 1, 4, 'k', 'a', 'k', 'a'}, 0, expect, 0, 8);
		assertArrayEquals(expect, listApdu.getBuffer());
		
		APDU calcApdu = new APDU(new byte[] {
			0x00, (byte) 0xa2, 0x00, 0x00, 0x10,
			0x7a, 0x04, 'k', 'a', 'k', 'a',
			0x7d, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 
			0x00
		});
		ykneoOath.process(calcApdu);
		assertArrayEquals(new byte[]{
				0x7d, 0x14, (byte) 0xb3, (byte) 0x99, (byte) 0xbd, (byte) 0xfc, (byte) 0x9d, 0x05, (byte) 0xd1, 0x2a, (byte) 0xc4, 0x35, (byte) 0xc4,
				(byte) 0xc8, (byte) 0xd6, (byte) 0xcb, (byte) 0xd2, 0x47, (byte) 0xc4, 0x0a, 0x30, (byte) 0xf1
		}, calcApdu.getBuffer());
		
		APDU delApdu = new APDU(new byte[] {
				0x00, 0x02, 0x00, 0x00, 0x06, 0x7a, 0x04, 0x6b, 0x61, 0x6b, 0x61
		});
		ykneoOath.process(delApdu);
		assertNull(OathObj.firstObject);
	}
}
