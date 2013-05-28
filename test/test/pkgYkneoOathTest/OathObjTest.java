package pkgYkneoOathTest;

/*
 * Copyright (c) 2013 Yubico AB
 * All rights reserved.
 */

import static org.junit.Assert.*;

import java.util.Arrays;

import org.junit.Test;

import pkgYkneoOath.OathObj;

public class OathObjTest {
	@Test
	public void TestCreate() {
		OathObj obj = new OathObj();
		obj.addObject();
		assertEquals(obj, OathObj.firstObject);
		obj.removeObject();
		assertEquals(null, OathObj.firstObject);
	}
	
	@Test
	public void TestAddSeveralAndRemove() {
		OathObj first = new OathObj();
		OathObj second = new OathObj();
		OathObj third = new OathObj();
		first.setName("first".getBytes(), (short)0, (short)5);
		second.setName("second".getBytes(), (short)0, (short)6);
		third.setName("third".getBytes(), (short)0, (short)5);
		first.addObject();
		second.addObject();
		third.addObject();
		assertEquals(first, OathObj.firstObject);
		assertEquals(second, first.nextObject);
		assertEquals(third, second.nextObject);
		assertEquals(third, OathObj.lastObject);
		OathObj obj = OathObj.findObject("first".getBytes(), (short)0, (short)5);
		assertEquals(first, obj);
		obj = OathObj.findObject("second".getBytes(), (short)0, (short)6);
		assertEquals(second, obj);
		obj = OathObj.findObject("third".getBytes(), (short)0, (short)5);
		assertEquals(third, obj);
		first.removeObject();
		assertEquals(null, first.nextObject);
		assertEquals(second, OathObj.firstObject);
		second.removeObject();
		assertEquals(null, second.nextObject);
		assertEquals(third, OathObj.firstObject);
		second.addObject();
		assertEquals(second, third.nextObject);
		assertEquals(second, OathObj.lastObject);
		third.removeObject();
		assertEquals(null, third.nextObject);
		assertEquals(second, OathObj.firstObject);
		second.removeObject();
		assertEquals(null, OathObj.firstObject);
		assertEquals(null, OathObj.lastObject);
	}
	
	/* sha-1 test vectors come from rfc 2202 */
	@Test
	public void TestSha1Case1() {
		OathObj obj = new OathObj();
		byte[] key = new byte[20];
		Arrays.fill(key, (byte)0x0b);
		obj.setKey(key,	(short) 0, OathObj.HMAC_SHA1, (short)20);
		byte[] res = new byte[20];
		obj.calculate("Hi There".getBytes(), (short)0, (short) 8, res, (short)0);
		byte[] expected = new byte[] {(byte) 0xb6, 0x17, 0x31, (byte) 0x86, 0x55, 0x05, 0x72, 0x64, (byte) 0xe2, (byte) 0x8b, (byte) 0xc0, (byte) 0xb6, (byte) 0xfb, 0x37, (byte) 0x8c, (byte) 0x8e, (byte) 0xf1, 0x46, (byte) 0xbe, 0x00};
		assertArrayEquals(expected, res);
	}
	
	@Test
	public void TestSha1Case2() {
		OathObj obj = new OathObj();
		obj.setKey("Jefe".getBytes(), (short)0, OathObj.HMAC_SHA1, (short)4);
		byte[] res = new byte[20];
		obj.calculate("what do ya want for nothing?".getBytes(), (short)0, (short)28, res, (short) 0);
		byte[] expected = new byte[] {(byte) 0xef, (byte) 0xfc, (byte) 0xdf, 0x6a, (byte) 0xe5, (byte) 0xeb, 0x2f, (byte) 0xa2, (byte) 0xd2, 0x74, 0x16, (byte) 0xd5, (byte) 0xf1, (byte) 0x84, (byte) 0xdf, (byte) 0x9c, 0x25, (byte) 0x9a, 0x7c, 0x79};
		assertArrayEquals(expected, res);
	}
	
	@Test
	public void TestSha1Case3() {
		OathObj obj = new OathObj();
		byte[] key = new byte[20];
		Arrays.fill(key, (byte)0xaa);
		obj.setKey(key, (short) 0, OathObj.HMAC_SHA1, (short)20);
		byte[] challenge = new byte[50];
		Arrays.fill(challenge, (byte)0xdd);
		byte[] res = new byte[20];
		obj.calculate(challenge, (short)0, (short)50, res, (short)0);
		byte[] expected = new byte[] {0x12, 0x5d, 0x73, 0x42, (byte) 0xb9, (byte) 0xac, 0x11, (byte) 0xcd, (byte) 0x91, (byte) 0xa3, (byte) 0x9a, (byte) 0xf4, (byte) 0x8a, (byte) 0xa1, 0x7b, 0x4f, 0x63, (byte) 0xf1, 0x75, (byte) 0xd3};
		assertArrayEquals(expected, res);
	}
	
	@Test
	public void TestSha1Case4() {
		OathObj obj = new OathObj();
		obj.setKey(new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19},
				(short)0, OathObj.HMAC_SHA1, (short)25);
		byte[] challenge = new byte[50];
		Arrays.fill(challenge, (byte)0xcd);
		byte[] res = new byte[20];
		obj.calculate(challenge, (short)0, (short)50, res, (short)0);
		byte[] expected = new byte[] {0x4c, (byte) 0x90, 0x07, (byte) 0xf4, 0x02, 0x62, 0x50, (byte) 0xc6, (byte) 0xbc, (byte) 0x84, 0x14, (byte) 0xf9, (byte) 0xbf, 0x50, (byte) 0xc8, 0x6c, 0x2d, 0x72, 0x35, (byte) 0xda};
		assertArrayEquals(expected, res);
	}
	
	@Test
	public void TestSha1Case5() {
		OathObj obj = new OathObj();
		byte[] key = new byte[20];
		Arrays.fill(key, (byte)0x0c);
		obj.setKey(key, (short)0, OathObj.HMAC_SHA1, (short)20);
		byte[] res = new byte[20];
		obj.calculate("Test With Truncation".getBytes(), (short)0, (short)20, res, (short)0);
		byte[] expected = new byte[] {0x4c, 0x1a, 0x03, 0x42, 0x4b, 0x55, (byte) 0xe0, 0x7f, (byte) 0xe7, (byte) 0xf2, 0x7b, (byte) 0xe1, (byte) 0xd5, (byte) 0x8b, (byte) 0xb9, 0x32, 0x4a, (byte) 0x9a, 0x5a, 0x04};
		assertArrayEquals(expected, res);
	}
	
	/* sha-256 test vectors come from rfc 4231 */
	@Test
	public void TestSha256Case1() {
		OathObj obj = new OathObj();
		byte[] key = new byte[20];
		Arrays.fill(key, (byte)0x0b);
		obj.setKey(key, (short)0, OathObj.HMAC_SHA256, (short)20);
		byte[] res = new byte[32];
		obj.calculate("Hi There".getBytes(), (short)0, (short)8, res, (short)0);
		byte[] expected = new byte[] {(byte) 0xb0, 0x34, 0x4c, 0x61, (byte) 0xd8, (byte) 0xdb, 0x38, 0x53, 0x5c, (byte) 0xa8, (byte) 0xaf, (byte) 0xce, (byte) 0xaf, 0x0b, (byte) 0xf1, 0x2b,
				(byte) 0x88, 0x1d, (byte) 0xc2, 0x00, (byte) 0xc9, (byte) 0x83, 0x3d, (byte) 0xa7, 0x26, (byte) 0xe9, 0x37, 0x6c, 0x2e, 0x32, (byte) 0xcf, (byte) 0xf7};
		assertArrayEquals(expected, res);
	}
	
	@Test
	public void TestSha256Case2() {
		OathObj obj = new OathObj();
		obj.setKey("Jefe".getBytes(), (short)0, OathObj.HMAC_SHA256, (short)4);
		byte[] res = new byte[32];
		byte[] challenge = "what do ya want for nothing?".getBytes();
		obj.calculate(challenge, (short)0, (short)challenge.length, res, (short)0);
		byte[] expected = new byte[] {0x5b, (byte) 0xdc, (byte) 0xc1, 0x46, (byte) 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, (byte) 0x95, 0x75, (byte) 0xc7,
				0x5a, 0x00, 0x3f, 0x08, (byte) 0x9d, 0x27, 0x39, (byte) 0x83, (byte) 0x9d, (byte) 0xec, 0x58, (byte) 0xb9, 0x64, (byte) 0xec, 0x38, 0x43};
		assertArrayEquals(expected, res);
	}
}