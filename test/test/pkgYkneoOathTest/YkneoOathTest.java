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
		list[1] = (byte) YkneoOath.LIST_INS;
		listApdu = new APDU(list);
	}
	
	@Test
	public void testEmptyList() {
		assertNull(OathObj.firstObject);
		ykneoOath.process(listApdu);
		byte[] buf = listApdu.getBuffer();
		assertEquals(YkneoOath.NAME_LIST_TAG, buf[0]);
		assertEquals(0, buf[1]);
	}
	
	@Test
	public void testLife() {
		APDU putApdu = new APDU(new byte[] {
				0x00, YkneoOath.PUT_INS, 0x00, 0x00, 0x1d,
				YkneoOath.NAME_TAG, 0x04, 'k', 'a', 'k', 'a',
				YkneoOath.KEY_TAG, 0x16, 0x21, 0x06, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
		});
		assertNull(OathObj.firstObject);
		ykneoOath.process(putApdu);
		assertNotNull(OathObj.firstObject);
		ykneoOath.process(listApdu);
		byte[] expect = new byte[256];
		System.arraycopy(new byte[] {YkneoOath.NAME_LIST_TAG, 6, 0x21, 4, 'k', 'a', 'k', 'a'}, 0, expect, 0, 8);
		assertArrayEquals(expect, listApdu.getBuffer());
		
		APDU calcApdu = new APDU(new byte[] {
			0x00, YkneoOath.CALCULATE_INS, 0x00, 0x00, 0x10,
			YkneoOath.NAME_TAG, 0x04, 'k', 'a', 'k', 'a',
			YkneoOath.CHALLENGE_TAG, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			0x00, 0x00
		});
		ykneoOath.process(calcApdu);
		assertArrayEquals(new byte[]{
				YkneoOath.RESPONSE_TAG, 0x15, 0x06, (byte) 0xb3, (byte) 0x99, (byte) 0xbd, (byte) 0xfc, (byte) 0x9d, 0x05, (byte) 0xd1, 0x2a, (byte) 0xc4, 0x35, (byte) 0xc4,
				(byte) 0xc8, (byte) 0xd6, (byte) 0xcb, (byte) 0xd2, 0x47, (byte) 0xc4, 0x0a, 0x30, (byte) 0xf1
		}, calcApdu.getBuffer());
		
		APDU delApdu = new APDU(new byte[] {
				0x00, YkneoOath.DELETE_INS, 0x00, 0x00, 0x06, YkneoOath.NAME_TAG, 0x04, 0x6b, 0x61, 0x6b, 0x61
		});
		ykneoOath.process(delApdu);
		assertEquals(false, OathObj.firstObject.isActive());
	}
	
	@Test
	public void testOverwrite() {
		APDU putApdu = new APDU(new byte[] {
			0x00, YkneoOath.PUT_INS, 0x00, 0x00, 0x1f,
			YkneoOath.NAME_TAG, 0x04, 'k', 'a', 'k', 'a',
			YkneoOath.KEY_TAG, 0x16, 0x21, 0x06, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
			YkneoOath.PROPERTY_TAG, 0x01
		});

		assertNull(OathObj.firstObject);
		ykneoOath.process(putApdu);
		assertNotNull(OathObj.firstObject);
		assertNull(OathObj.firstObject.nextObject);
		ykneoOath.process(listApdu);
		byte[] expect = new byte[256];
		System.arraycopy(new byte[] {(byte) YkneoOath.NAME_LIST_TAG, 6, 0x21, 4, 'k', 'a', 'k', 'a'}, 0, expect, 0, 8);
		assertArrayEquals(expect, listApdu.getBuffer());

		APDU calcApdu = new APDU(new byte[] {
				0x00, YkneoOath.CALCULATE_INS, 0x00, 0x00, 0x10,
				YkneoOath.NAME_TAG, 0x04, 'k', 'a', 'k', 'a',
				YkneoOath.CHALLENGE_TAG, 0x08, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				0x00, 0x00
		});
		ykneoOath.process(calcApdu);
		assertArrayEquals(new byte[]{
				YkneoOath.RESPONSE_TAG, 0x15, 0x06, 0x79, 0x3e, 0x1b, (byte) 0xbd, (byte) 0xbf, (byte) 0xa7, 0x75, (byte) 0xa8, 0x63,(byte) 0xcc,
				(byte) 0x80, 0x02, (byte) 0xce, (byte) 0xe4, (byte) 0xbd, 0x6c, (byte) 0xd7, (byte) 0xce, (byte) 0xb8, (byte) 0xcd
		}, calcApdu.getBuffer());
		ykneoOath.process(putApdu);
		
		// make sure there is only one object after overwrite
		assertEquals(OathObj.firstObject, OathObj.lastObject);
		assertNull(OathObj.firstObject.nextObject);
		
		byte[] buf = listApdu.getBuffer();
		Arrays.fill(buf, (byte)0x00);
		buf[1] = YkneoOath.LIST_INS;
		ykneoOath.process(listApdu);
		System.arraycopy(new byte[] {YkneoOath.NAME_LIST_TAG, 6, 0x21, 4, 'k', 'a', 'k', 'a'}, 0, expect, 0, 8);
		assertArrayEquals(expect, listApdu.getBuffer());
		
		calcApdu = new APDU(new byte[] {
				0x00, YkneoOath.CALCULATE_INS, 0x00, 0x00, 0x10,
				YkneoOath.NAME_TAG, 0x04, 'k', 'a', 'k', 'a',
				YkneoOath.CHALLENGE_TAG, 0x08, (byte) 0xff, (byte) 0x00, (byte) 0xff, (byte) 0x00, (byte) 0xff, (byte) 0x00, (byte) 0xff, (byte) 0x00,
				0x00, 0x00
		});
		ykneoOath.process(calcApdu);
		assertArrayEquals(new byte[] {
				YkneoOath.RESPONSE_TAG, 0x15, 0x06, 0x3b, 0x0e, 0x3c, 0x63, 0x1c, 0x01, 0x67, (byte) 0xb0, (byte) 0x93, (byte) 0xa5,
				(byte) 0xec, (byte) 0xb9, 0x09, 0x7d, 0x0b, (byte) 0x8e, (byte) 0x9a, (byte) 0xcc, 0x2f, 0x7f
		}, calcApdu.getBuffer());
	}
	
	@Test
	public void testAuth() {
		byte[] buf = new byte[256];
		byte[] key = new byte[] {'k', 'a', 'k', 'a', ' ', 'b', 'l', 'a', 'h', 'o', 'n', 'g', 'a'};
		byte[] chal = new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
		byte[] resp = new byte[] {0x0c, 0x42, (byte) 0x8e, (byte) 0x9c, (byte) 0xba, (byte) 0xa3, (byte) 0xb3, (byte) 0xab, 0x18, 0x53, (byte) 0xd8, 0x79, (byte) 0xb9, (byte) 0xd2, 0x26, (byte) 0xf7, (byte) 0xce, (byte) 0xcc, 0x4a, 0x7a};
		buf[1] = YkneoOath.SET_CODE_INS;
		int offs = 5;
		buf[offs++] = YkneoOath.KEY_TAG;
		buf[offs++] = (byte) (key.length + 1);
		buf[offs++] = OathObj.HMAC_SHA1 | OathObj.TOTP_TYPE; // type
		System.arraycopy(key, 0, buf, offs, key.length);
		offs += key.length;
		buf[offs++] = YkneoOath.CHALLENGE_TAG;
		buf[offs++] = (byte) chal.length;
		System.arraycopy(chal, 0, buf, offs, chal.length);
		offs += chal.length;
		buf[offs++] = YkneoOath.RESPONSE_TAG;
		buf[offs++] = (byte) resp.length;
		System.arraycopy(resp, 0, buf, offs, resp.length);
		
		APDU apdu = new APDU(buf);
		ykneoOath.process(apdu);
		
		Arrays.fill(buf, (byte)0);
		ykneoOath.mockSelectApplet(true);
		ykneoOath.process(apdu);
		offs = 15;
		assertEquals(YkneoOath.CHALLENGE_TAG, buf[offs++]);
		assertEquals(0x08, buf[offs++]);
		byte[] data = new byte[8];
		System.arraycopy(buf, offs, data, 0, 8);
		byte[] resp2 = hmacSha1(key, data);
		
		Arrays.fill(buf, (byte)0);
		buf[1] = (byte) YkneoOath.VALIDATE_INS;
		offs = 5;
		buf[offs++] = YkneoOath.RESPONSE_TAG;
		buf[offs++] = (byte) resp2.length;
		System.arraycopy(resp2, 0, buf, offs, resp2.length);
		offs += resp2.length;
		buf[offs++] = YkneoOath.CHALLENGE_TAG;
		buf[offs++] = (byte) chal.length;
		System.arraycopy(chal, 0, buf, offs, chal.length);
		ykneoOath.process(apdu);
	}
	
	@Test
	public void testBothOath() {
		byte[] key = new byte[] {'f', 'o', 'o', ' ', 'b', 'a', 'r'};
		byte[] totpName = new byte[] {'t', 'o', 't', 'p'};
		byte[] hotpName = new byte[] {'h', 'o', 't', 'p'};
		byte[] buf = new byte[256];
		byte digits = 6;
		buf[1] = YkneoOath.PUT_INS;
		int offs = 5;
		buf[offs++] = YkneoOath.NAME_TAG;
		buf[offs++] = (byte) totpName.length;
		System.arraycopy(totpName, 0, buf, offs, totpName.length);
		offs += totpName.length;
		buf[offs++] = YkneoOath.KEY_TAG;
		buf[offs++] = (byte) (key.length + 2);
		buf[offs++] = OathObj.TOTP_TYPE | OathObj.HMAC_SHA1;
		buf[offs++] = digits;
		System.arraycopy(key, 0, buf, offs, key.length);
		offs += key.length;
		APDU apdu = new APDU(buf);
		ykneoOath.process(apdu);
		buf[7] = 'h';
		buf[13] = OathObj.HOTP_TYPE | OathObj.HMAC_SHA1;
		ykneoOath.process(apdu);
		
		byte[] chal = new byte[] {0x00, 0x00, 0x00, 0x00, 0x02, (byte) 0xbc, (byte) 0xad, (byte) 0xc8};
		byte[] resp = new byte[] {0x3d, (byte) 0xc6, (byte) 0xbf, 0x3d};
		Arrays.fill(buf, (byte)0);
		buf[1] = YkneoOath.CALCULATE_ALL_INS;
		buf[3] = 1;
		buf[5] = YkneoOath.CHALLENGE_TAG;
		buf[6] = (byte) chal.length;
		System.arraycopy(chal, 0, buf, 7, chal.length);
		ykneoOath.process(apdu);
		
		byte[] buf2 = new byte[256];
		offs = 0;
		buf2[offs++] = YkneoOath.NAME_TAG;
		buf2[offs++] = (byte) totpName.length;
		System.arraycopy(totpName, 0, buf2, offs, totpName.length);
		offs += totpName.length;
		buf2[offs++] = YkneoOath.T_RESPONSE_TAG;
		buf2[offs++] = (byte) (resp.length + 1);
		buf2[offs++] = digits;
		System.arraycopy(resp, 0, buf2, offs, resp.length);
		offs += resp.length;
		buf2[offs++] = YkneoOath.NAME_TAG;
		buf2[offs++] = (byte) hotpName.length;
		System.arraycopy(hotpName, 0, buf2, offs, hotpName.length);
		offs += hotpName.length;
		buf2[offs++] = YkneoOath.NO_RESPONSE_TAG;
		buf2[offs++] = 0x01;
		buf2[offs++] = digits;
		assertArrayEquals(buf2, buf);
		
		Arrays.fill(buf, (byte)0);
		buf[1] = YkneoOath.CALCULATE_INS;
		buf[3] = 1;
		offs = 5;
		buf[offs++] = YkneoOath.NAME_TAG;
		buf[offs++] = (byte) hotpName.length;
		System.arraycopy(hotpName, 0, buf, offs, hotpName.length);
		offs += hotpName.length;
		buf[offs++] = YkneoOath.CHALLENGE_TAG;
		ykneoOath.process(apdu);
		byte[] expect = new byte[] {0x17, (byte) 0xfa, 0x2d, 0x40};
		resp = new byte[4];
		System.arraycopy(buf, 3, resp, 0, resp.length);
		assertArrayEquals(expect, resp);
	}
	
	private static byte[] hmacSha1(byte[] key, byte[] data) {
		byte[] ret = null;
        try {
            Key signingKey = new SecretKeySpec(key, "HmacSHA1");
			Mac mac = Mac.getInstance("HmacSHA1");
	        mac.init(signingKey);
	        ret = mac.doFinal(data);
		} catch (NoSuchAlgorithmException e) {
			fail(e.getMessage());
		} catch (InvalidKeyException e) {
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
