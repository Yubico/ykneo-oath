package pkgYkneoOath;

/*
 * Copyright (c) 2013 Yubico AB
 * All rights reserved.
 */

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;

public class OathObj {
	public static final byte HMAC_MASK = 0x0f;
	public static final byte HMAC_SHA1 = 0x01;
	public static final byte HMAC_SHA256 = 0x02;
	
	public static final byte OATH_MASK = (byte) 0xf0;
	public static final byte HOTP_TYPE = 0x10;
	public static final byte TOTP_TYPE = 0x20;
	
	public static final byte PROP_ALWAYS_INCREASING = 1 << 0;
	
	private static final short _0 = 0;
	
	private static final byte hmac_buf_size = 64;
	
	public static OathObj firstObject;
	public static OathObj lastObject;
	public OathObj nextObject;
	
	private byte[] name;
	private byte type;
	private byte digits;
	private short counter = 0;

	private byte[] inner;
	private byte[] outer;
	private static MessageDigest sha;
	private static MessageDigest sha256;
	private MessageDigest digest;
	
	private byte[] lastChal;
	private short lastOffs;
	private byte props;
	
	private static byte[] scratchBuf;
	
	public OathObj() {
		inner = new byte[hmac_buf_size];
		outer = new byte[hmac_buf_size];
		
		if(scratchBuf == null) {
			scratchBuf = JCSystem.makeTransientByteArray((short) 128, JCSystem.CLEAR_ON_DESELECT);
		}
	}
	
	public void setKey(byte[] buf, short offs, byte type, short len) {
		if((type & HMAC_MASK) != HMAC_SHA1 && (type & HMAC_MASK) != HMAC_SHA256) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		if((type & OATH_MASK) != HOTP_TYPE && (type & OATH_MASK) != TOTP_TYPE) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		if(len > hmac_buf_size) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		if((type & HMAC_MASK) == HMAC_SHA1) {
			if(sha == null) {
				sha = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
			}
			digest = sha;
		} else if((type & HMAC_MASK) == HMAC_SHA256) {
			if(sha256 == null) {
				sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
			}
			digest = sha256;
		}
		
		this.type = type;
		this.counter = 0;
		Util.arrayFillNonAtomic(inner, _0, hmac_buf_size, (byte) 0x36);
		Util.arrayFillNonAtomic(outer, _0, hmac_buf_size, (byte) 0x5c);
        for (short i = 0; i < len; i++, offs++) {
            inner[i] = (byte) (buf[offs] ^ 0x36);
            outer[i] = (byte) (buf[offs] ^ 0x5c);
        }
	}
	
	public void setDigits(byte digits) {
		this.digits = digits;
	}
	
	public byte getDigits() {
		return digits;
	}
	
	public byte getType() {
		return type;
	}
	
	public void setName(byte[] buf, short offs, short len) {
		if(name == null || len != name.length) {
			name = new byte[len];
		}
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
		if((props & PROP_ALWAYS_INCREASING) == PROP_ALWAYS_INCREASING) {
			if(lastChal == null) {
				lastChal = new byte[hmac_buf_size];
			} else {
				Util.arrayFillNonAtomic(lastChal, _0, hmac_buf_size, (byte) 0);
				lastOffs = 0;
			}
		}
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
		byte[] buf = null;
		
		if((type & OATH_MASK) == TOTP_TYPE) {
			if(len > hmac_buf_size || len == 0) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			}
			if((props & PROP_ALWAYS_INCREASING) == PROP_ALWAYS_INCREASING) {
				short thisOffs = (short) (hmac_buf_size - len);
				short i = lastOffs < thisOffs ? lastOffs : thisOffs;
				for(; i < hmac_buf_size; i++) {
					if(i < thisOffs) {
						if(lastChal[i] == 0) {
							continue;
						} else {
							ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
						}
					} else {
						break;
					}
				}
				short offs = (short) (i - thisOffs + chalOffs);
				byte compRes = Util.arrayCompare(chal, offs, lastChal, i, len);
				if(compRes == -1) {
					ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
				}
				lastOffs = thisOffs;
				Util.arrayCopy(chal, chalOffs, lastChal, thisOffs, len);
			}
			buf = chal;
		} else if((type & OATH_MASK) == HOTP_TYPE) {
			Util.arrayFillNonAtomic(scratchBuf, _0, (short)8, (byte)0);
			Util.setShort(scratchBuf, (short) 6, counter++);
			buf = scratchBuf;
			chalOffs = 0;
			len = 8;
		} else {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		
		digest.reset();
		digest.update(inner, _0, hmac_buf_size);
		short digestLen = digest.doFinal(buf, chalOffs, len, dest, destOffs);
		
		digest.reset();
		digest.update(outer, _0, hmac_buf_size);
		return digest.doFinal(dest, destOffs, digestLen, dest, destOffs);
	}
	
	public short calculateTruncated(byte[] chal, short chalOffs, short len,
			byte[] dest, short destOffs) {
		short length = calculate(chal, chalOffs, len, scratchBuf, _0);
		short offs = (short) (scratchBuf[(short)(length - 1)] & 0xf);
		dest[destOffs++] = (byte) (scratchBuf[offs++] & 0x7f);
		dest[destOffs++] = scratchBuf[offs++];
		dest[destOffs++] = scratchBuf[offs++];
		dest[destOffs++] = scratchBuf[offs++];
		return 4;
	}
	
	public short getDigestLength() {
		return digest.getLength();
	}
}
