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
	public void testPut() {
		APDU putApdu = new APDU(new byte[] {
				0x00, 0x01, 0x00, 0x00, 0x1c,
				0x7a, 0x04, 'k', 'a', 'k', 'a',
				0x7b, 0x01, 0x14, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
		});
		assertNull(OathObj.firstObject);
		ykneoOath.process(putApdu);
		assertNotNull(OathObj.firstObject);
		ykneoOath.process(listApdu);
		byte[] buf = listApdu.getBuffer();
		assertEquals((byte)0xa1, buf[0]);
		assertEquals(6, buf[1]);
		assertEquals(1, buf[2]);
		assertEquals(4, buf[3]);
		byte[] name = new byte[4];
		System.arraycopy(buf, 4, name, 0, 4);
		assertArrayEquals(new byte[] {'k', 'a', 'k', 'a'}, name);
	}
}
