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
		byte[] chal = "Hi There".getBytes();
		byte[] res = new byte[20];
		obj.calculate(chal, (short)0, (short) chal.length, res, (short)0);
		byte[] expected = new byte[] {(byte) 0xb6, 0x17, 0x31, (byte) 0x86, 0x55, 0x05, 0x72, 0x64, (byte) 0xe2, (byte) 0x8b, (byte) 0xc0, (byte) 0xb6, (byte) 0xfb, 0x37, (byte) 0x8c, (byte) 0x8e, (byte) 0xf1, 0x46, (byte) 0xbe, 0x00};
		assertArrayEquals(expected, res);
	}
}
