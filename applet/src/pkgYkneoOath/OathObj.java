package pkgYkneoOath;

/*
 * Copyright (c) 2013 Yubico AB
 * All rights reserved.
 */

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.MessageDigest;

public class OathObj {
	public static final byte HMAC_SHA1 = 0x01;
	public static final byte HMAC_SHA256 = 0x02;
	
	public static final byte PROP_ALWAYS_INCREASING = 1 << 0;
	
	private static final short _0 = 0;
	
	private static final byte hmac_buf_size = 64;
	
	public static OathObj firstObject;
	public static OathObj lastObject;
	public OathObj nextObject;
	
	private byte[] name;
	public byte type;

	private byte[] inner;
	private byte[] outer;
	private static MessageDigest sha;
	private static MessageDigest sha256;
	
	private byte[] lastChal;
	private byte props;
	
	public OathObj() {
		inner = new byte[hmac_buf_size];
		outer = new byte[hmac_buf_size];
	}
	
	public void setKey(byte[] buf, short offs, byte type, short len) {
		if(type != HMAC_SHA1 && type != HMAC_SHA256) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		if(len > hmac_buf_size) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		if(type == HMAC_SHA1 && sha == null) {
			sha = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
		} else if(type == HMAC_SHA256 && sha256 == null) {
			sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
		}
		
		this.type = type;
		Util.arrayFillNonAtomic(inner, _0, hmac_buf_size, (byte) 0x36);
		Util.arrayFillNonAtomic(outer, _0, hmac_buf_size, (byte) 0x5c);
        for (short i = 0; i < len; i++, offs++) {
            inner[i] = (byte) (buf[offs] ^ 0x36);
            outer[i] = (byte) (buf[offs] ^ 0x5c);
        }
	}
	
	public void setName(byte[] buf, short offs, short len) {
		name = new byte[len];
		Util.arrayCopy(buf, offs, name, _0, len);
	}
	
	public short getName(byte[] buf, short offs) {
		Util.arrayCopy(name, _0, buf, offs, (short) name.length);
		return (short) name.length;
	}
	
	public short getNameLength() {
		return (short) name.length;
	}
	
	public void setProp(byte props) {
		this.props = props;
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
		this.nextObject = null;
	}
	
	public static OathObj findObject(byte[] name, short offs, short len) {
		OathObj object = firstObject;
		while(object != null) {
			if(len != object.name.length) {
				object = object.nextObject;
				continue;
			}
			if(Util.arrayCompare(name, offs, object.name, _0, len) == 0) {
				break;
			}
			object = object.nextObject;
		}
		return object;
	}

	public short calculate(byte[] chal, short chalOffs, short len, byte[] dest,
			short destOffs) {
		MessageDigest digest = null;
		if(type == HMAC_SHA1) {
			digest = sha;
		} else if(type == HMAC_SHA256) {
			digest = sha256;
		}
		
		if(len > hmac_buf_size || len == 0) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		
		if((props & PROP_ALWAYS_INCREASING) == PROP_ALWAYS_INCREASING) {
			if(lastChal == null) {
				lastChal = new byte[hmac_buf_size];
			}
			for(short i = 0; i < len; i++) {
				short offs = (short) (i + chalOffs);
				if(chal[offs] > lastChal[i]) {
					break;
				} else if(lastChal[i] == 0 || lastChal[i] == chal[offs]) {
					continue;
				} else {
					ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
				}
			}
			Util.arrayCopy(chal, chalOffs, lastChal, _0, len);
		}
		
		digest.reset();
		digest.update(inner, _0, hmac_buf_size);
		short digestLen = digest.doFinal(chal, chalOffs, len, dest, destOffs);
		
		digest.reset();
		digest.update(outer, _0, hmac_buf_size);
		return digest.doFinal(dest, destOffs, digestLen, dest, destOffs);
	}
}
