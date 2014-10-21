package pkgYkneoOathTest;

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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javacard.framework.ISOException;

import org.junit.After;
import org.junit.Test;

import pkgYkneoOath.OathObj;

public class OathObjTest {
	@After
	public void tearDown() {
		OathObj.firstObject = null;
		OathObj.lastObject = null;
	}

	@Test
	public void TestCreate() {
		OathObj obj = new OathObj();
		obj.addObject();
		assertEquals(obj, OathObj.firstObject);
		obj.setActive(false);
		assertEquals(false, OathObj.firstObject.isActive());
	}

	@Test
	public void TestAddSeveralAndRemove() {
		OathObj first = OathObj.getFreeObject();
		first.setName("first".getBytes(), (short)0, (short)5);
		first.setActive(true);
		OathObj second = OathObj.getFreeObject();
		second.setName("second".getBytes(), (short)0, (short)6);
		second.setActive(true);
		OathObj third = OathObj.getFreeObject();
		third.setName("third".getBytes(), (short)0, (short)5);
		third.setActive(true);
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
	}

	@Test
	public void TestIncreasing() {
		OathObj obj = new OathObj();
		obj.setKey("Test".getBytes(), (short)0, (byte)(OathObj.TOTP_TYPE | OathObj.HMAC_SHA1), (short)4);
		obj.setProp(OathObj.PROP_ALWAYS_INCREASING);
		byte[] resp = new byte[20];

		short ret = obj.calculate(new byte[] {0x00, 0x00,  0x00,  0x01}, (short)0, (short)4, resp, (short)0);
		assertEquals(ret, 20);
		ret = obj.calculate(new byte[] {0x00, 0x00,  0x00,  0x02}, (short)0, (short)4, resp, (short)0);
		assertEquals(ret, 20);
		try {
			obj.calculate(new byte[] {0x00, 0x00,  0x00,  0x01}, (short)0, (short)4, resp, (short)0);
		} catch(ISOException e) {
			assertEquals(0x6982, e.getReason());
		}
	}

	@Test
	public void TestIncreasingDiffLen() {
		OathObj obj = new OathObj();
		obj.setKey("Kaka".getBytes(), (short)0, (byte)(OathObj.TOTP_TYPE | OathObj.HMAC_SHA1), (short)4);
		obj.setProp(OathObj.PROP_ALWAYS_INCREASING);
		byte[] resp = new byte[20];

		short ret = obj.calculate(new byte[] {0x00, 0x01, 0x02, 0x03}, (short)0, (short)4, resp, (short)0);
		assertEquals(ret, 20);
		ret = obj.calculate(new byte[] {0x00, 0x00, 0x01, 0x02, 0x04}, (short)0, (short)5, resp, (short)0);
		assertEquals(ret, 20);
		ret = obj.calculate(new byte[] {0x01, 0x02, 0x05}, (short)0, (short)3, resp, (short)0);
		assertEquals(ret, 20);
	}

	@Test
	public void TestDeactivate() {
		OathObj first = OathObj.getFreeObject();
		first.setActive(true);
		OathObj second = OathObj.getFreeObject();
		second.setActive(true);
		assertNotSame(first, second);
		second.setActive(false);
		OathObj third = OathObj.getFreeObject();
		third.setActive(true);
		assertEquals(second, third);
		first.setActive(false);
		second = OathObj.getFreeObject();
		second.setActive(true);
		assertEquals(first, second);
	}

	@Test
	public void TestHotpIMF1() {
		List<byte[]> expected = new ArrayList<byte[]>();
		expected.add(new byte[] {0x4d, (byte) 0xee, 0x58, 0x64});
		expected.add(new byte[] {0x25, (byte) 0xc5, 0x33, (byte) 0x92});
		expected.add(new byte[] {0x5c, 0x22, (byte) 0x81, 0x73});
		expected.add(new byte[] {0x1b, 0x01, 0x6b, 0x42});
		expected.add(new byte[] {0x29, (byte) 0x80, (byte) 0xc9, (byte) 0xab});
		expected.add(new byte[] {0x1d, (byte) 0xc5, (byte) 0xea, (byte) 0xb6});
		expected.add(new byte[] {0x1e, (byte) 0xd8, (byte) 0xb6, 0x09});
		expected.add(new byte[] {0x35, 0x54, (byte) 0x96, 0x2a});
		expected.add(new byte[] {0x08, (byte) 0x94, 0x24, (byte) 0xa0});
		expected.add(new byte[] {0x6e, (byte) 0xf1, 0x4a, 0x38});

		OathObj obj = new OathObj();
		byte[] key = "12345678901234567890".getBytes();
		byte[] imf = new byte[] {0x00, (byte) 0xff, (byte) 0xff, (byte) 0xfe};
		obj.setKey(key, (short)0, (byte) (OathObj.HOTP_TYPE | OathObj.HMAC_SHA1), (short)key.length);
		obj.setImf(imf, (short) 0);
		for(byte[] expect : expected) {
			byte[] dest = new byte[4];
			obj.calculateTruncated(new byte[8], (short)0, (short) 8, dest, (short)0);
			assertArrayEquals(expect, dest);
		}
	}

	/* sha-1 test vectors come from rfc 2202 */
	@Test
	public void TestSha1Case1() {
		OathObj obj = new OathObj();
		byte[] key = new byte[20];
		Arrays.fill(key, (byte)0x0b);
		obj.setKey(key,	(short) 0, (byte)(OathObj.TOTP_TYPE | OathObj.HMAC_SHA1), (short)20);
		byte[] res = new byte[20];
		obj.calculate("Hi There".getBytes(), (short)0, (short) 8, res, (short)0);
		byte[] expected = new byte[] {(byte) 0xb6, 0x17, 0x31, (byte) 0x86, 0x55, 0x05, 0x72, 0x64, (byte) 0xe2, (byte) 0x8b, (byte) 0xc0, (byte) 0xb6, (byte) 0xfb, 0x37, (byte) 0x8c, (byte) 0x8e, (byte) 0xf1, 0x46, (byte) 0xbe, 0x00};
		assertArrayEquals(expected, res);
	}

	@Test
	public void TestSha1Case2() {
		OathObj obj = new OathObj();
		obj.setKey("Jefe".getBytes(), (short)0, (byte)(OathObj.TOTP_TYPE | OathObj.HMAC_SHA1), (short)4);
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
		obj.setKey(key, (short) 0, (byte)(OathObj.TOTP_TYPE | OathObj.HMAC_SHA1), (short)20);
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
				(short)0, (byte)(OathObj.TOTP_TYPE | OathObj.HMAC_SHA1), (short)25);
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
		obj.setKey(key, (short)0, (byte)(OathObj.TOTP_TYPE | OathObj.HMAC_SHA1), (short)20);
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
		obj.setKey(key, (short)0, (byte)(OathObj.TOTP_TYPE | OathObj.HMAC_SHA256), (short)20);
		byte[] res = new byte[32];
		obj.calculate("Hi There".getBytes(), (short)0, (short)8, res, (short)0);
		byte[] expected = new byte[] {(byte) 0xb0, 0x34, 0x4c, 0x61, (byte) 0xd8, (byte) 0xdb, 0x38, 0x53, 0x5c, (byte) 0xa8, (byte) 0xaf, (byte) 0xce, (byte) 0xaf, 0x0b, (byte) 0xf1, 0x2b,
				(byte) 0x88, 0x1d, (byte) 0xc2, 0x00, (byte) 0xc9, (byte) 0x83, 0x3d, (byte) 0xa7, 0x26, (byte) 0xe9, 0x37, 0x6c, 0x2e, 0x32, (byte) 0xcf, (byte) 0xf7};
		assertArrayEquals(expected, res);
	}

	@Test
	public void TestSha256Case2() {
		OathObj obj = new OathObj();
		obj.setKey("Jefe".getBytes(), (short)0, (byte)(OathObj.TOTP_TYPE | OathObj.HMAC_SHA256), (short)4);
		byte[] res = new byte[32];
		byte[] challenge = "what do ya want for nothing?".getBytes();
		obj.calculate(challenge, (short)0, (short)challenge.length, res, (short)0);
		byte[] expected = new byte[] {0x5b, (byte) 0xdc, (byte) 0xc1, 0x46, (byte) 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, (byte) 0x95, 0x75, (byte) 0xc7,
				0x5a, 0x00, 0x3f, 0x08, (byte) 0x9d, 0x27, 0x39, (byte) 0x83, (byte) 0x9d, (byte) 0xec, 0x58, (byte) 0xb9, 0x64, (byte) 0xec, 0x38, 0x43};
		assertArrayEquals(expected, res);
	}

	@Test
	public void TestSha256Case3() {
		OathObj obj = new OathObj();
		byte[] key = new byte[20];
		Arrays.fill(key, (byte)0xaa);
		obj.setKey(key, (short)0, (byte)(OathObj.TOTP_TYPE | OathObj.HMAC_SHA256), (short)20);
		byte[] challenge = new byte[50];
		Arrays.fill(challenge, (byte)0xdd);
		byte[] res = new byte[32];
		obj.calculate(challenge, (short)0, (short)50, res, (short)0);
		byte[] expected = new byte[] {0x77, 0x3e, (byte) 0xa9, 0x1e, 0x36, (byte) 0x80, 0x0e, 0x46, (byte) 0x85, 0x4d, (byte) 0xb8, (byte) 0xeb, (byte) 0xd0, (byte) 0x91, (byte) 0x81, (byte) 0xa7,
				0x29, 0x59, 0x09, (byte) 0x8b, 0x3e, (byte) 0xf8, (byte) 0xc1, 0x22, (byte) 0xd9, 0x63, 0x55, 0x14, (byte) 0xce, (byte) 0xd5, 0x65, (byte) 0xfe};
		assertArrayEquals(expected, res);
	}

	@Test
	public void TestSha256Case4() {
		OathObj obj = new OathObj();
		obj.setKey(new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19}, (short)0, (byte)(OathObj.TOTP_TYPE | OathObj.HMAC_SHA256), (short)25);
		byte[] challenge = new byte[50];
		Arrays.fill(challenge, (byte)0xcd);
		byte[] res = new byte[32];
		obj.calculate(challenge, (short)0, (short)50, res, (short)0);
		byte[] expected = new byte[] {(byte) 0x82, 0x55, (byte) 0x8a, 0x38, (byte) 0x9a, 0x44, 0x3c, 0x0e, (byte) 0xa4, (byte) 0xcc, (byte) 0x81, (byte) 0x98, (byte) 0x99, (byte) 0xf2, 0x08, 0x3a,
				(byte) 0x85, (byte) 0xf0, (byte) 0xfa, (byte) 0xa3, (byte) 0xe5, 0x78, (byte) 0xf8, 0x07, 0x7a, 0x2e, 0x3f, (byte) 0xf4, 0x67, 0x29, 0x66, 0x5b};
		assertArrayEquals(expected, res);
	}

	/* TOTP test vectors from rfc 6238 */
	@Test
	public void TestSha1Trunc() {
		OathObj obj = new OathObj();
		obj.setKey(new byte[] {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30}, (short)0, (byte)(OathObj.TOTP_TYPE | OathObj.HMAC_SHA1), (short)20);
		Map<byte[], byte[]> challengeMap = new HashMap<byte[], byte[]>();
		challengeMap.put(new byte[] {0, 0, 0, 0, 0, 0, 0, 1}, new byte[] { 0x41, 0x39, 0x7e, (byte) 0xea });
		challengeMap.put(new byte[] {0, 0, 0, 0, 0x02, 0x35, 0x23, (byte) 0xec}, new byte[] { 0x36, 0x10, (byte) 0xf8, 0x4c });
		challengeMap.put(new byte[] {0, 0, 0, 0, 0x02, 0x35, 0x23, (byte) 0xed}, new byte[] { 0x18, (byte) 0xad, (byte) 0xe8, (byte) 0xa7 });
		challengeMap.put(new byte[] {0, 0, 0, 0, 0x02, 0x73, (byte) 0xef, 0x07}, new byte[] { 0x29, 0x11, 0x65, 0x64 });
		challengeMap.put(new byte[] {0, 0, 0, 0, 0x03, (byte) 0xf9, 0x40, (byte) 0xaa}, new byte[] { 0x7b, 0x56, (byte) 0xb1, 0x3d });
		challengeMap.put(new byte[] {0, 0, 0, 0, 0x27, (byte) 0xbc, (byte) 0x86, (byte) 0xaa}, new byte[] { 0x57, 0x57, (byte) 0x83, (byte) 0xaa });

		for(byte[] chal : challengeMap.keySet()) {
			byte[] result = new byte[4];
			obj.calculateTruncated(chal, (short)0, (short) chal.length, result, (short)0);
			String challenge = "";
			for(byte c : chal) {
				challenge += String.format("0x%02x ", c);
			}
			assertArrayEquals("challenge: " + challenge, challengeMap.get(chal), result);		}
	}

	@Test
	public void TestSha256Trunc() {
		OathObj obj = new OathObj();
		obj.setKey(new byte[] {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32}, (short)0, (byte)(OathObj.TOTP_TYPE | OathObj.HMAC_SHA256), (short)32);
		Map<byte[], byte[]> challengeMap = new HashMap<byte[], byte[]>();
		challengeMap.put(new byte[] {0, 0, 0, 0, 0, 0, 0, 1}, new byte[] { 0x2c, 0x78, (byte) 0xe0, 0x4e });
		challengeMap.put(new byte[] {0, 0, 0, 0, 0x02, 0x35, 0x23, (byte) 0xec}, new byte[] { 0x5d, 0x77, 0x13, 0x26 });
		challengeMap.put(new byte[] {0, 0, 0, 0, 0x02, 0x35, 0x23, (byte) 0xed}, new byte[] { 0x45, (byte) 0x8f, (byte) 0xf6, (byte) 0x92 });
		challengeMap.put(new byte[] {0, 0, 0, 0, 0x02, 0x73, (byte) 0xef, 0x07}, new byte[] { 0x05, 0x79, 0x0d, (byte) 0xa0 });
		challengeMap.put(new byte[] {0, 0, 0, 0, 0x03, (byte) 0xf9, 0x40, (byte) 0xaa}, new byte[] { 0x6a, (byte) 0xbb, (byte) 0xe5, 0x49 });
		challengeMap.put(new byte[] {0, 0, 0, 0, 0x27, (byte) 0xbc, (byte) 0x86, (byte) 0xaa}, new byte[] { 0x2e, 0x5b, 0x55, (byte) 0xea });

		for(byte[] chal : challengeMap.keySet()) {
			byte[] result = new byte[4];
			obj.calculateTruncated(chal, (short)0, (short) chal.length, result, (short)0);
			String challenge = "";
			for(byte c : chal) {
				challenge += String.format("0x%02x ", c);
			}
			assertArrayEquals("challenge: " + challenge, challengeMap.get(chal), result);
		}
	}

	// HOTP test vectors from rfc 4226
	@Test
	public void TestHotp() {
		byte[] key = "12345678901234567890".getBytes();
		List<byte[]> expecteds = new ArrayList<byte[]>();
		expecteds.add(new byte[] {0x4c, (byte) 0x93, (byte) 0xcf, 0x18});
		expecteds.add(new byte[] {0x41, 0x39, 0x7e, (byte) 0xea});
		expecteds.add(new byte[] {0x8, 0x2f, (byte) 0xef, 0x30});
		expecteds.add(new byte[] {0x66, (byte) 0xef, 0x76, 0x55});
		expecteds.add(new byte[] {0x61, (byte) 0xc5, (byte) 0x93, (byte) 0x8a});
		expecteds.add(new byte[] {0x33, (byte) 0xc0, (byte) 0x83, (byte) 0xd4});
		expecteds.add(new byte[] {0x72, 0x56, (byte) 0xc0, 0x32});
		expecteds.add(new byte[] {0x4, (byte) 0xe5, (byte) 0xb3, (byte) 0x97});
		expecteds.add(new byte[] {0x28, 0x23, 0x44, 0x3f});
		expecteds.add(new byte[] {0x26, 0x79, (byte) 0xdc, 0x69});

		OathObj obj = new OathObj();
		obj.setKey(key, (short)0, (byte)(OathObj.HOTP_TYPE | OathObj.HMAC_SHA1), (short) key.length);

		for(int i = 0; i < 10; i++) {
			byte[] result = new byte[4];
			byte[] chal = new byte[8];
			obj.calculateTruncated(chal, (short)0, (short) 8, result, (short)0);
			assertArrayEquals("at number " + i, expecteds.get(i), result);
		}
	}

	@Test
	public void TestHugeHotp() {
		Properties props = new Properties();
		InputStream in = getClass().getResourceAsStream("/testdata.properties");
		if(in == null) {
			fail("couldn't find testdata.properties.");
		}
		try {
			props.load(in);
		} catch (IOException e) {
			fail("failed to load testdata.properties: " + e.getMessage());
		}

		List<String> keys = new ArrayList<String>(props.stringPropertyNames());
		Collections.sort(keys);

		OathObj obj = OathObj.getFreeObject();
		obj.setKey(new byte[] {'b', 'l', 'a', 'h', 'o', 'n', 'g', 'a'},
				(short) 0, (byte) (OathObj.HOTP_TYPE | OathObj.HMAC_SHA1), (short)8);
		obj.setImf(new byte[] {0xf, (byte) 0xff, (byte) 0xff, (byte) 0xff}, (short)0);

		for(String key : keys) {
			int value = Integer.parseInt(props.getProperty(key));
			byte[] expected = new byte[4];
			expected[0] = (byte) (value >>> 24);
			expected[1] = (byte) (value >>> 16);
			expected[2] = (byte) (value >>> 8);
			expected[3] = (byte) value;

			byte[] result = new byte[4];
			obj.calculateTruncated(new byte[] {}, (short)0, (short)0, result, (short)0);
			assertArrayEquals(expected, result);
		}
	}
}