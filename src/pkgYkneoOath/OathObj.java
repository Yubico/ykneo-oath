package pkgYkneoOath;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class OathObj {
	public static final byte HMAC_SHA1 = 0x01;
	public static final byte HMAC_SHA256 = 0x02;
	
	private static short _0 = 0;
	
	private byte[] key;
	private byte[] name;
	private byte[] type;
	
	private byte[] lastChal;
	private byte[] props;
	
	public void setKey(byte[] buf, short offs, byte type) {
		short len = 0;
		if(type == HMAC_SHA1) {
			len = 20;
		} else if(type == HMAC_SHA256) {
			len = 32;
		} else {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		Util.arrayCopy(buf, offs, key, _0, len);
	}
}
