package pkgYkneoOath;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class OathObj {
	public static final byte HMAC_SHA1 = 0x01;
	public static final byte HMAC_SHA256 = 0x02;
	
	private static short _0 = 0;
	
	private static OathObj firstObject;
	private static OathObj lastObject;
	private OathObj nextObject;
	
	private byte[] key;
	private byte[] name;
	private short nameLen;
	private byte[] type;
	
	private byte[] lastChal;
	private byte[] props;
	
	public void setKey(byte[] buf, short offs, byte type) {
		short len = 0;
		if(type == HMAC_SHA1) {
			len = 20;
			type = HMAC_SHA1;
		} else if(type == HMAC_SHA256) {
			len = 32;
			type = HMAC_SHA256;
		} else {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		key = new byte[len];
		Util.arrayCopy(buf, offs, key, _0, len);
	}
	
	public void setName(byte[] buf, short offs, short len) {
		name = new byte[len];
		Util.arrayCopy(buf, offs, name, _0, len);
		nameLen = len;
	}
	
	public void addObject() {
		if(firstObject == null) {
			firstObject = lastObject = this;
		} else if(firstObject == lastObject) {
			firstObject.nextObject = lastObject = this;
		} else {
			lastObject.nextObject = lastObject = this;
		}
	}
	
	public void removeObject() {
		if(firstObject == lastObject && firstObject == this) {
			firstObject = lastObject = null;
		} else if(firstObject == this) {
			firstObject = this.nextObject;
		} else {
			OathObj object = firstObject;
			while(object.nextObject != this) {
				object = object.nextObject;
			}
			object.nextObject = nextObject;
			if(lastObject == this) {
				lastObject = object;
			}
		}
	}
	
	public static OathObj findObject(byte[] name, short offs, short len) {
		OathObj object = firstObject;
		while(object != null) {
			short length = len;
			if(length > object.nameLen) {
				length = object.nameLen;
			}
			if(Util.arrayCompare(name, offs, object.name, _0, length) == 0) {
				break;
			}
			object = object.nextObject;
		}
		return object;
	}
}
