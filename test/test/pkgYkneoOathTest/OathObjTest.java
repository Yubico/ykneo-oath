package pkgYkneoOathTest;

import static org.junit.Assert.*;

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
	public void TestSha1Case1() {
		OathObj obj = new OathObj();
		obj.setKey(new byte[] {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b},
				(short) 0, OathObj.HMAC_SHA1, (short)20);
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
}
