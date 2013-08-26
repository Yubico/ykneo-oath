package pkgYkneoOathTest;

/*
 * Copyright (c) 2013 Yubico AB
 * All rights reserved.
 */

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

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
				0x00, 0x01, 0x00, 0x00, 0x1d,
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
	
	@Test
	public void testOverwrite() {
		APDU putApdu = new APDU(new byte[] {
			0x00, 0x01, 0x00, 0x00, 0x1f,
			0x7a, 0x04, 'k', 'a', 'k', 'a',
			0x7b, 0x01, 0x14, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
			0x7c, 0x01
		});

		assertNull(OathObj.firstObject);
		ykneoOath.process(putApdu);
		assertNotNull(OathObj.firstObject);
		assertNull(OathObj.firstObject.nextObject);
		ykneoOath.process(listApdu);
		byte[] expect = new byte[256];
		System.arraycopy(new byte[] {(byte) 0xa1, 6, 1, 4, 'k', 'a', 'k', 'a'}, 0, expect, 0, 8);
		assertArrayEquals(expect, listApdu.getBuffer());

		APDU calcApdu = new APDU(new byte[] {
				0x00, (byte) 0xa2, 0x00, 0x00, 0x10,
				0x7a, 0x04, 'k', 'a', 'k', 'a',
				0x7d, 0x08, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, 
				0x00
		});
		ykneoOath.process(calcApdu);
		assertArrayEquals(new byte[]{
				0x7d, 0x14, 0x79, 0x3e, 0x1b, (byte) 0xbd, (byte) 0xbf, (byte) 0xa7, 0x75, (byte) 0xa8, 0x63,(byte) 0xcc,
				(byte) 0x80, 0x02, (byte) 0xce, (byte) 0xe4, (byte) 0xbd, 0x6c, (byte) 0xd7, (byte) 0xce, (byte) 0xb8, (byte) 0xcd
		}, calcApdu.getBuffer());
		ykneoOath.process(putApdu);
		
		// make sure there is only one object after overwrite
		assertEquals(OathObj.firstObject, OathObj.lastObject);
		assertNull(OathObj.firstObject.nextObject);
		
		byte[] buf = listApdu.getBuffer();
		Arrays.fill(buf, (byte)0x00);
		buf[1] = (byte)0xa1;
		ykneoOath.process(listApdu);
		System.arraycopy(new byte[] {(byte) 0xa1, 6, 1, 4, 'k', 'a', 'k', 'a'}, 0, expect, 0, 8);
		assertArrayEquals(expect, listApdu.getBuffer());
		
		calcApdu = new APDU(new byte[] {
				0x00, (byte) 0xa2, 0x00, 0x00, 0x10,
				0x7a, 0x04, 'k', 'a', 'k', 'a',
				0x7d, 0x08, (byte) 0xff, (byte) 0x00, (byte) 0xff, (byte) 0x00, (byte) 0xff, (byte) 0x00, (byte) 0xff, (byte) 0x00, 
				0x00
		});
		ykneoOath.process(calcApdu);
		assertArrayEquals(new byte[] {
				0x7d, 0x14, 0x3b, 0x0e, 0x3c, 0x63, 0x1c, 0x01, 0x67, (byte) 0xb0, (byte) 0x93, (byte) 0xa5,
				(byte) 0xec, (byte) 0xb9, 0x09, 0x7d, 0x0b, (byte) 0x8e, (byte) 0x9a, (byte) 0xcc, 0x2f, 0x7f
		}, calcApdu.getBuffer());
	}
	
	@Test
	public void testAuth() {
		byte[] buf = new byte[256];
		byte[] key = new byte[] {'k', 'a', 'k', 'a', ' ', 'b', 'l', 'a', 'h', 'o', 'n', 'g', 'a'};
		byte[] chal = new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
		byte[] resp = new byte[] {0x0c, 0x42, (byte) 0x8e, (byte) 0x9c, (byte) 0xba, (byte) 0xa3, (byte) 0xb3, (byte) 0xab, 0x18, 0x53, (byte) 0xd8, 0x79, (byte) 0xb9, (byte) 0xd2, 0x26, (byte) 0xf7, (byte) 0xce, (byte) 0xcc, 0x4a, 0x7a};
		buf[1] = 0x03;
		int offs = 5;
		buf[offs++] = 0x7b;
		buf[offs++] = 1; // type
		buf[offs++] = (byte) key.length;
		System.arraycopy(key, 0, buf, offs, key.length);
		offs += key.length;
		buf[offs++] = 0x7c;
		buf[offs++] = (byte) chal.length;
		System.arraycopy(chal, 0, buf, offs, chal.length);
		offs += chal.length;
		buf[offs++] = 0x7d;
		buf[offs++] = (byte) resp.length;
		System.arraycopy(resp, 0, buf, offs, resp.length);
		
		APDU apdu = new APDU(buf);
		ykneoOath.process(apdu);
		
		Arrays.fill(buf, (byte)0);
		ykneoOath.mockSelectApplet(true);
		ykneoOath.process(apdu);
		offs = 10;
		assertEquals(0x7f, buf[offs++]);
		assertEquals(0x08, buf[offs++]);
		byte[] data = new byte[8];
		System.arraycopy(buf, offs, data, 0, 8);
		byte[] resp2 = hmacSha1(key, data);
		
		Arrays.fill(buf, (byte)0);
		buf[1] = (byte) 0xa3;
		offs = 5;
		buf[offs++] = 0x7f;
		buf[offs++] = (byte) resp2.length;
		System.arraycopy(resp2, 0, buf, offs, resp2.length);
		offs += resp2.length;
		buf[offs++] = 0x7c;
		buf[offs++] = (byte) chal.length;
		System.arraycopy(chal, 0, buf, offs, chal.length);
		ykneoOath.process(apdu);
	}
	
	private static byte[] hmacSha1(byte[] key, byte[] data) {
		byte[] ret = null;
        try {
            Key signingKey = new SecretKeySpec(key, "HmacSHA1");
			Mac mac = Mac.getInstance("HmacSHA1");
	        mac.init(signingKey);
	        ret = mac.doFinal(data);
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			fail(e.getMessage());
		}
        return ret;
	}
	
	@SuppressWarnings("unused")
	private void dumpArray(byte[] buf) {
		String out = "";
		for(byte b : buf) {
			out += String.format("%02x ", b);
		}
		System.out.println(out);
	}
}
