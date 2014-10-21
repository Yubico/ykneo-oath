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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javacard.framework.AID;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import pkgYkneoOath.OathObj;
import pkgYkneoOath.YkneoOath;

import com.licel.jcardsim.base.Simulator;

public class YkneoOathTest {
	Simulator simulator;
	static final byte[] oathAid = new byte[] {(byte) 0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01, 0x01};
	static final byte[] listApdu = new byte[] {0x00, YkneoOath.LIST_INS, 0x00, 0x00};
	static final AID aid = new AID(oathAid, (short)0, (byte)oathAid.length);


	@After
	public void tearDown() {
		OathObj.firstObject = null;
		OathObj.lastObject = null;
	}

	@Before
	public void setup() {
		byte[] params = new byte[oathAid.length + 1];
		params[0] = (byte) oathAid.length;
		System.arraycopy(oathAid, 0, params, 1, oathAid.length);

		simulator = new Simulator();
		simulator.resetRuntime();
		simulator.installApplet(aid, YkneoOath.class, params, (short)0, (byte) params.length);
		simulator.selectApplet(aid);
	}

	@Test
	public void testEmptyList() {
		assertNull(OathObj.firstObject);
		byte[] resp = simulator.transmitCommand(listApdu);
		assertArrayEquals(new byte[] {(byte) 0x90, 0x00}, resp);
	}

	@Test
	public void testLife() {
		assertNull(OathObj.firstObject);
		byte[] resp = simulator.transmitCommand(new byte[] {
				0x00, YkneoOath.PUT_INS, 0x00, 0x00, 0x1d,
				YkneoOath.NAME_TAG, 0x04, 'k', 'a', 'k', 'a',
				YkneoOath.KEY_TAG, 0x16, 0x21, 0x06, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
		});
		assertNotNull(OathObj.firstObject);
		resp = simulator.transmitCommand(listApdu);
		byte[] expect = new byte[] {YkneoOath.NAME_LIST_TAG, 5, 0x21, 'k', 'a', 'k', 'a', (byte) 0x90, 0x00};
		assertArrayEquals(expect, resp);

		resp = simulator.transmitCommand(new byte[] {
				0x00, YkneoOath.CALCULATE_INS, 0x00, 0x00, 0x10,
				YkneoOath.NAME_TAG, 0x04, 'k', 'a', 'k', 'a',
				YkneoOath.CHALLENGE_TAG, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01});
		byte[] expected = new byte[]{
				YkneoOath.RESPONSE_TAG, 0x15, 0x06, (byte) 0xb3, (byte) 0x99, (byte) 0xbd, (byte) 0xfc, (byte) 0x9d, 0x05, (byte) 0xd1, 0x2a, (byte) 0xc4, 0x35, (byte) 0xc4,
				(byte) 0xc8, (byte) 0xd6, (byte) 0xcb, (byte) 0xd2, 0x47, (byte) 0xc4, 0x0a, 0x30, (byte) 0xf1, (byte) 0x90, 0x00};
		assertArrayEquals(expected, resp);

		simulator.transmitCommand(new byte[] {
				0x00, YkneoOath.DELETE_INS, 0x00, 0x00, 0x06, YkneoOath.NAME_TAG, 0x04, 0x6b, 0x61, 0x6b, 0x61
		});
		assertEquals(false, OathObj.firstObject.isActive());
	}

	@Test
	public void testOverwrite() {
		byte[] putApdu = new byte[] {
				0x00, YkneoOath.PUT_INS, 0x00, 0x00, 0x1f,
				YkneoOath.NAME_TAG, 0x04, 'k', 'a', 'k', 'a',
				YkneoOath.KEY_TAG, 0x16, 0x21, 0x06, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
				YkneoOath.PROPERTY_TAG, 0x01 };

		assertNull(OathObj.firstObject);
		simulator.transmitCommand(putApdu);
		assertNotNull(OathObj.firstObject);
		assertNull(OathObj.firstObject.nextObject);
		byte[] resp = simulator.transmitCommand(listApdu);
		byte[] expect = new byte[] {(byte) YkneoOath.NAME_LIST_TAG, 5, 0x21, 'k', 'a', 'k', 'a', (byte) 0x90, 0x00};
		assertArrayEquals(expect, resp);

		resp = simulator.transmitCommand(new byte[] {
				0x00, YkneoOath.CALCULATE_INS, 0x00, 0x00, 0x10,
				YkneoOath.NAME_TAG, 0x04, 'k', 'a', 'k', 'a',
				YkneoOath.CHALLENGE_TAG, 0x08, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff }
		);
		expect = new byte[]{
				YkneoOath.RESPONSE_TAG, 0x15, 0x06, 0x79, 0x3e, 0x1b, (byte) 0xbd, (byte) 0xbf, (byte) 0xa7, 0x75, (byte) 0xa8, 0x63,(byte) 0xcc,
				(byte) 0x80, 0x02, (byte) 0xce, (byte) 0xe4, (byte) 0xbd, 0x6c, (byte) 0xd7, (byte) 0xce, (byte) 0xb8, (byte) 0xcd, (byte) 0x90, 0x00};
		assertArrayEquals(expect, resp);
		simulator.transmitCommand(putApdu);

		// make sure there is only one object after overwrite
		assertEquals(OathObj.firstObject, OathObj.lastObject);
		assertNull(OathObj.firstObject.nextObject);

		resp = simulator.transmitCommand(listApdu);
		expect = new byte[] {YkneoOath.NAME_LIST_TAG, 5, 0x21, 'k', 'a', 'k', 'a', (byte) 0x90, 0x00};
		assertArrayEquals(expect, resp);

		resp = simulator.transmitCommand(new byte[] {
				0x00, YkneoOath.CALCULATE_INS, 0x00, 0x00, 0x10,
				YkneoOath.NAME_TAG, 0x04, 'k', 'a', 'k', 'a',
				YkneoOath.CHALLENGE_TAG, 0x08, (byte) 0xff, (byte) 0x00, (byte) 0xff, (byte) 0x00, (byte) 0xff, (byte) 0x00, (byte) 0xff, (byte) 0x00});
		expect = new byte[] {
				YkneoOath.RESPONSE_TAG, 0x15, 0x06, 0x3b, 0x0e, 0x3c, 0x63, 0x1c, 0x01, 0x67, (byte) 0xb0, (byte) 0x93, (byte) 0xa5,
				(byte) 0xec, (byte) 0xb9, 0x09, 0x7d, 0x0b, (byte) 0x8e, (byte) 0x9a, (byte) 0xcc, 0x2f, 0x7f, (byte) 0x90, 0x00 };
		assertArrayEquals(expect, resp);
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

		simulator.transmitCommand(buf);

		Arrays.fill(buf, (byte)0);
		simulator.reset();
		resp = simulator.selectAppletWithResult(aid);
		offs = 15;
		assertEquals(YkneoOath.CHALLENGE_TAG, resp[offs++]);
		assertEquals(0x08, resp[offs++]);
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
		simulator.transmitCommand(buf);
	}

	@Test
	public void testBothOath() {
		byte digits = 6;
		byte[] buf = new byte[] {0x00, YkneoOath.PUT_INS, 0x00, 0x00, 0, YkneoOath.NAME_TAG, 0x04, 't', 'o', 't', 'p',
				YkneoOath.KEY_TAG, 0x09, OathObj.TOTP_TYPE | OathObj.HMAC_SHA1, digits, 'f', 'o', 'o', ' ', 'b', 'a', 'r'};
		simulator.transmitCommand(buf);
		buf[7] = 'h';
		buf[13] = OathObj.HOTP_TYPE | OathObj.HMAC_SHA1;
		simulator.transmitCommand(buf);

		byte[] chal = new byte[] {0x00, YkneoOath.CALCULATE_ALL_INS, 0x00, 0x01, 0xa, YkneoOath.CHALLENGE_TAG, 0x08, 0x00, 0x00, 0x00, 0x00, 0x02, (byte) 0xbc, (byte) 0xad, (byte) 0xc8};
		byte[] expected = new byte[] {YkneoOath.NAME_TAG, 0x04, 't', 'o', 't', 'p', YkneoOath.T_RESPONSE_TAG, 0x05, digits, 0x3d, (byte) 0xc6, (byte) 0xbf, 0x3d,
				YkneoOath.NAME_TAG, 0x04, 'h', 'o', 't', 'p', YkneoOath.NO_RESPONSE_TAG, 0x01, digits, (byte) 0x90, 0x00};
		byte []	resp = simulator.transmitCommand(chal);
		assertArrayEquals(expected, resp);

		chal = new byte[] {0x00, YkneoOath.CALCULATE_INS, 0x00, 0x01, 0x07, YkneoOath.NAME_TAG, 0x04, 'h', 'o', 't', 'p', YkneoOath.CHALLENGE_TAG};
		resp = simulator.transmitCommand(chal);
		expected = new byte[] {YkneoOath.T_RESPONSE_TAG, 0x05, digits, 0x17, (byte) 0xfa, 0x2d, 0x40, (byte) 0x90, 0x00};
		assertArrayEquals(expected, resp);
	}

	@Test
	public void testDelete() {
		String key = "blahonga!";
		String firstName = "one";
		String secondName = "two";
		String thirdName = "three";
		byte type = OathObj.HMAC_SHA1 | OathObj.TOTP_TYPE;

		byte[] buf = new byte[256];
		buf[1] = YkneoOath.PUT_INS;
		int offs = 5;
		buf[offs++] = YkneoOath.NAME_TAG;
		buf[offs++] = (byte) firstName.length();
		int nameoffs = offs;
		System.arraycopy(firstName.getBytes(), 0, buf, offs, firstName.length());
		offs += firstName.length();
		buf[offs++] = YkneoOath.KEY_TAG;
		buf[offs++] = (byte) (key.length() + 2);
		buf[offs++] = type;
		buf[offs++] = 6;
		System.arraycopy(key.getBytes(), 0, buf, offs, key.length());
		simulator.transmitCommand(buf);
		assertEquals(firstName.length(), secondName.length());
		System.arraycopy(secondName.getBytes(), 0, buf, nameoffs, secondName.length());
		simulator.transmitCommand(buf);
		byte[] list = simulator.transmitCommand(listApdu);
		offs = 0;
		assertEquals(YkneoOath.NAME_LIST_TAG, list[offs++]);
		assertEquals(firstName.length() + 1, list[offs++]);
		assertEquals(type, list[offs++]);
		byte[] name = new byte[3];
		System.arraycopy(list, offs, name, 0, firstName.length());
		assertArrayEquals(firstName.getBytes(), name);
		offs += firstName.length();
		assertEquals(YkneoOath.NAME_LIST_TAG, list[offs++]);
		assertEquals(secondName.length() + 1, list[offs++]);
		assertEquals(type, list[offs++]);
		System.arraycopy(list, offs, name, 0, secondName.length());
		assertArrayEquals(secondName.getBytes(), name);
		Arrays.fill(buf, (byte)0);
		buf[1] = YkneoOath.DELETE_INS;
		offs = 5;
		buf[offs++] = YkneoOath.NAME_TAG;
		buf[offs++] = (byte) firstName.length();
		System.arraycopy(firstName.getBytes(), 0, buf, offs, firstName.length());
		simulator.transmitCommand(buf);
		list = simulator.transmitCommand(listApdu);
		offs = 0;
		assertEquals(YkneoOath.NAME_LIST_TAG, list[offs++]);
		assertEquals(secondName.length() + 1, list[offs++]);
		assertEquals(type, list[offs++]);
		System.arraycopy(list, offs, name, 0, 3);
		assertArrayEquals(secondName.getBytes(), name);
		Arrays.fill(buf, (byte)0);
		buf[1] = YkneoOath.PUT_INS;
		offs = 5;
		buf[offs++] = YkneoOath.NAME_TAG;
		buf[offs++] = (byte) thirdName.length();
		System.arraycopy(thirdName.getBytes(), 0, buf, offs, thirdName.length());
		offs += thirdName.length();
		buf[offs++] = YkneoOath.KEY_TAG;
		buf[offs++] = (byte) (key.length() + 2);
		buf[offs++] = type;
		buf[offs++] = 6;
		System.arraycopy(key.getBytes(), 0, buf, offs, key.length());
		simulator.transmitCommand(buf);
		list = simulator.transmitCommand(listApdu);
		offs = 0;
		assertEquals(YkneoOath.NAME_LIST_TAG, list[offs++]);
		assertEquals(thirdName.length() + 1, list[offs++]);
		assertEquals(type, list[offs++]);
		name = new byte[thirdName.length()];
		System.arraycopy(list, offs, name, 0, thirdName.length());
		assertArrayEquals(thirdName.getBytes(), name);
		offs += thirdName.length();
		assertEquals(YkneoOath.NAME_LIST_TAG, list[offs++]);
		assertEquals(secondName.length() + 1, list[offs++]);
		assertEquals(type, list[offs++]);
		name = new byte[secondName.length()];
		System.arraycopy(list, offs, name, 0, secondName.length());
		assertArrayEquals(secondName.getBytes(), name);
	}

	@Test
	public void testHotpIMFOverwrite() {
		byte[] key = "kaka".getBytes();
		byte[] imf = new byte[] {(byte) 0xff, 0x00, (byte) 0xff, (byte) 0xff};
		byte[] name = "kaka".getBytes();

		byte[] buf = new byte[256];
		buf[1] = YkneoOath.PUT_INS;
		int offs = 5;
		buf[offs++] = YkneoOath.NAME_TAG;
		buf[offs++] = (byte) name.length;
		System.arraycopy(name, 0, buf, offs, name.length);
		offs += name.length;
		buf[offs++] = YkneoOath.KEY_TAG;
		buf[offs++] = (byte) (key.length + 2);
		buf[offs++] = OathObj.HMAC_SHA1 | OathObj.HOTP_TYPE;
		buf[offs++] = 6;
		System.arraycopy(key, 0, buf, offs, key.length);
		offs += key.length;
		buf[offs++] = YkneoOath.IMF_TAG;
		buf[offs++] = (byte) imf.length;
		System.arraycopy(imf, 0, buf, offs, imf.length);
		simulator.transmitCommand(buf);
		Arrays.fill(buf, (byte)0);
		buf[1] = YkneoOath.CALCULATE_INS;
		buf[3] = 1; // truncate
		offs = 5;
		buf[offs++] = YkneoOath.NAME_TAG;
		buf[offs++] = (byte) name.length;
		System.arraycopy(name, 0, buf, offs, name.length);
		offs += name.length;
		buf[offs++] = YkneoOath.CHALLENGE_TAG;
		byte[] resp = simulator.transmitCommand(buf);
		byte[] expected = new byte[] {YkneoOath.T_RESPONSE_TAG, 5, 6, 0x45, (byte) 0xd9, 0x0f, 0x25, (byte) 0x90, 0x00};
		assertArrayEquals(expected, resp);
		byte[] chal = new byte[] {0x00, YkneoOath.CALCULATE_INS, 0, 1, (byte) (name.length + 2), YkneoOath.NAME_TAG, (byte) name.length, 'k', 'a', 'k', 'a', YkneoOath.CHALLENGE_TAG};
		resp = simulator.transmitCommand(chal);
		offs = 3;
		expected[offs++] = 0x1b;
		expected[offs++] = (byte) 0xc5;
		expected[offs++] = 0x4a;
		expected[offs++] = (byte) 0x85;
		assertArrayEquals(expected, resp);

		byte[] put = new byte[] {0x00, YkneoOath.PUT_INS, 0x00, 0x00, (byte) (name.length + 2 + key.length + 4), YkneoOath.NAME_TAG, (byte) name.length, 'k', 'a', 'k', 'a',
				YkneoOath.KEY_TAG, (byte) (key.length + 2),  OathObj.HMAC_SHA1 | OathObj.HOTP_TYPE, 6, 'k', 'a', 'k', 'a'};
		simulator.transmitCommand(put);

		byte[] calc = new byte[] {0x00, YkneoOath.CALCULATE_INS, 0x00, 0x01, (byte) (name.length + 3), YkneoOath.NAME_TAG, (byte) name.length, 'k', 'a', 'k', 'a', YkneoOath.CHALLENGE_TAG};
		resp = simulator.transmitCommand(calc);
		offs = 3;
		expected[offs++] = 0x16;
		expected[offs++] = 0x53;
		expected[offs++] = 0x24;
		expected[offs++] = (byte) 0xdb;
		assertArrayEquals(expected, resp);
		resp = simulator.transmitCommand(calc);
		offs = 3;
		expected[offs++] = 0x53;
		expected[offs++] = (byte) 0xed;
		expected[offs++] = 0x5e;
		expected[offs++] = (byte) 0xb2;
		assertArrayEquals(expected, resp);
	}

	@Test
	public void testMoreHotpIMF() {
		byte[] key = new byte[] {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
				0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30};
		byte[] imf = new byte[] {0x00, 0x00, 0x00, 0x01};
		byte[] name = "kaka".getBytes();

		byte[] buf = new byte[256];
		buf[1] = YkneoOath.PUT_INS;
		int offs = 5;
		buf[offs++] = YkneoOath.NAME_TAG;
		buf[offs++] = (byte) name.length;
		System.arraycopy(name, 0, buf, offs, name.length);
		offs += name.length;
		buf[offs++] = YkneoOath.KEY_TAG;
		buf[offs++] = (byte) (key.length + 2);
		buf[offs++] = OathObj.HMAC_SHA1 | OathObj.HOTP_TYPE;
		buf[offs++] = 6;
		System.arraycopy(key, 0, buf, offs, key.length);
		offs += key.length;
		buf[offs++] = YkneoOath.IMF_TAG;
		buf[offs++] = (byte) imf.length;
		System.arraycopy(imf, 0, buf, offs, imf.length);
		simulator.transmitCommand(buf);

		byte[] calc = new byte[] {0x00, YkneoOath.CALCULATE_INS, 0x00, 0x01, (byte) (name.length + 2), YkneoOath.NAME_TAG, (byte) name.length, 'k', 'a', 'k', 'a', YkneoOath.CHALLENGE_TAG};
		byte[] resp = simulator.transmitCommand(calc);
		byte[] expected = new byte[] {YkneoOath.T_RESPONSE_TAG, 5, 6, 0x41, 0x39, 0x7e, (byte) 0xea, (byte) 0x90, 0x00};
		assertArrayEquals(expected, resp);
	}

	@Test
	public void testReset() {
		byte[] resp = simulator.selectAppletWithResult(aid);
		byte[] resp2 = simulator.selectAppletWithResult(aid);
		assertArrayEquals(resp,  resp2);
		simulator.transmitCommand(new byte[] {0, 4, (byte) 0xde, (byte) 0xad});
		resp2 = simulator.selectAppletWithResult(aid);
		assertEquals(false, Arrays.equals(resp, resp2));
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
