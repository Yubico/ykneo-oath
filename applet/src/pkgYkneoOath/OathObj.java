package pkgYkneoOath;

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

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
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
	public static final short NAME_LEN = 64;
	public static final byte IMF_LEN = 4;

	public OathObj nextObject;

	private OathList list;
	private byte[] name;
	private short nameLen;
	private byte type;
	private byte digits;
	private short counter = 0;
	private byte[] imf;
	private boolean active = false;

	private byte[] inner;
	private byte[] outer;
	private MessageDigest digest;

	private byte[] lastChal;
	private short lastOffs;
	private byte props;

	public OathObj(OathList list) {
		inner = new byte[hmac_buf_size];
		outer = new byte[hmac_buf_size];
		this.list = list;
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
			if(list.sha == null) {
				list.sha = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
			}
			digest = list.sha;
		} else if((type & HMAC_MASK) == HMAC_SHA256) {
			if(list.sha256 == null) {
				list.sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
			}
			digest = list.sha256;
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
		if(name == null) {
			name = new byte[NAME_LEN];
		}
		nameLen = len;
		Util.arrayCopy(buf, offs, name, _0, len);
	}

	public short getName(byte[] buf, short offs) {
		Util.arrayCopy(name, _0, buf, offs, (short) nameLen);
		return (short) nameLen;
	}

	public short getNameLength() {
		return (short) nameLen;
	}

        public boolean nameEquals(byte[] other, short offs) {
                return Util.arrayCompare(other, offs, name, _0, (short) nameLen) == 0;
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
		if(list.firstObject == null) {
			list.firstObject = list.lastObject = this;
		} else if(list.firstObject == list.lastObject) {
			list.firstObject.nextObject = list.lastObject = this;
		} else {
			list.lastObject.nextObject = list.lastObject = this;
		}
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
			Util.arrayFillNonAtomic(list.scratchBuf, _0, (short)8, (byte)0);
			if(imf == null || (imf[0] == 0 && imf[1] == 0 && imf[2] == 0 && imf[3] == 0)) {
				Util.setShort(list.scratchBuf, (short) 6, counter);
			} else {
				Util.arrayCopyNonAtomic(imf, _0, list.scratchBuf, (short)4, IMF_LEN);
				short carry = 0;
				short ctr1 = (short) ((counter >>> 8) & 0x00ff);
				short ctr2 = (short) (counter & 0x00ff);
	        	for(byte j = 7; j > 0; j--) {
	        		short place = (short) (list.scratchBuf[j] & 0x00ff);
	        		if(j == 7) {
	        			place += ctr2;
	        		} else if(j == 6) {
	        			place += ctr1;
	        		}
	        		place += carry;
	        		carry = (byte) (place >>> 8);
	        		list.scratchBuf[j] = (byte) (place);
	        	}
			}
			counter++;
			buf = list.scratchBuf;
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
		short length = calculate(chal, chalOffs, len, list.scratchBuf, _0);
		short offs = (short) (list.scratchBuf[(short)(length - 1)] & 0xf);
		dest[destOffs++] = (byte) (list.scratchBuf[offs++] & 0x7f);
		dest[destOffs++] = list.scratchBuf[offs++];
		dest[destOffs++] = list.scratchBuf[offs++];
		dest[destOffs++] = list.scratchBuf[offs++];
		return 4;
	}

	public short getDigestLength() {
		return digest.getLength();
	}

	public boolean isActive() {
		return active;
	}

	public void setActive(boolean active) {
		this.active = active;
	}

	public void setImf(byte[] buf, short offs) {
		if(imf == null) {
			imf = new byte[IMF_LEN];
		}
		for(byte i = 0; i < IMF_LEN; i++) {
			imf[i] = buf[offs++];
		}
	}

	public void clearImf() {
		if(imf != null) {
			Util.arrayFillNonAtomic(imf, _0, IMF_LEN, (byte)0);
		}
	}
}
