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

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.RandomData;

public class YkneoOath extends Applet {

	public static final byte NAME_TAG = 0x71;
    public static final byte NAME_LIST_TAG = 0x72;
    public static final byte KEY_TAG = 0x73;
    public static final byte CHALLENGE_TAG = 0x74;
    public static final byte RESPONSE_TAG = 0x75;
    public static final byte T_RESPONSE_TAG = 0x76;
    public static final byte NO_RESPONSE_TAG = 0x77;
    public static final byte PROPERTY_TAG = 0x78;
    public static final byte VERSION_TAG = 0x79;

    public static final byte PUT_INS = 0x01;
    public static final byte DELETE_INS = 0x02;
    public static final byte SET_CODE_INS = 0x03;
    public static final byte RESET_INS = 0x04;

    public static final byte LIST_INS = (byte)0xa1;
    public static final byte CALCULATE_INS = (byte)0xa2;
    public static final byte VALIDATE_INS = (byte)0xa3;
    public static final byte CALCULATE_ALL_INS = (byte)0xa4;
	
	private static final short _0 = 0;

	private static final byte CHALLENGE_LENGTH = 8;
	
	private byte[] tempBuf;

	private OathObj authObj;
	private OathObj scratchAuth;
	private byte[] authState;
	
	private RandomData rng;
	
	private byte[] identity;
	
	private static final byte[] version = {0x00,0x00,0x02};

	public YkneoOath() {
		tempBuf = JCSystem.makeTransientByteArray((short) 512, JCSystem.CLEAR_ON_DESELECT);
		authState = JCSystem.makeTransientByteArray((short)2, JCSystem.CLEAR_ON_DESELECT);
		rng = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
		
		identity = new byte[CHALLENGE_LENGTH];
		rng.generateData(identity, _0, CHALLENGE_LENGTH);
		
		authObj = new OathObj();
		scratchAuth = new OathObj();
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new YkneoOath().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	public void process(APDU apdu) {
		if (selectingApplet()) {
			byte[] buf = apdu.getBuffer();
			short offs = 0;
			buf[offs++] = VERSION_TAG;
			buf[offs++] = (byte)version.length;
			Util.arrayCopyNonAtomic(version, _0, buf, offs, (short) version.length);
			offs += (byte) version.length;
			buf[offs++] = NAME_TAG;
			short nameLen = (short) identity.length;
			buf[offs++] = (byte) nameLen;
			Util.arrayCopyNonAtomic(identity, _0, buf, offs, nameLen);
			offs += nameLen;

			// if the authobj is set add a challenge
			if(authObj.isActive()) {
				buf[offs++] = CHALLENGE_TAG;
				buf[offs++] = CHALLENGE_LENGTH;
				rng.generateData(buf, offs, CHALLENGE_LENGTH);
				authObj.calculate(buf, offs, CHALLENGE_LENGTH, tempBuf, _0);
				offs += CHALLENGE_LENGTH;
			}
			apdu.setOutgoingAndSend(_0, offs);
			return;
		}

		byte[] buf = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		short sendLen = 0;
		
		byte p1 = buf[ISO7816.OFFSET_P1];
		byte p2 = buf[ISO7816.OFFSET_P2];
		short p1p2 = Util.makeShort(p1, p2);
		byte ins = buf[ISO7816.OFFSET_INS];
		
		if(authObj.isActive() && ins != VALIDATE_INS && ins != RESET_INS) {
			if(authState[1] != 1) {
				ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			}
		}
		
		switch (ins) {
		case PUT_INS: // put
			if(p1p2 == 0x0000) {
				handlePut(buf);
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			}
			break;
		case DELETE_INS: // delete
			if(p1p2 == 0x0000) {
				handleDelete(buf);
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			}
			break;
		case SET_CODE_INS: // set code
			if(p1p2 == 0x0000) {
				handleChangeCode(buf);
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			}
			break;
		case RESET_INS: // reset
			if(p1p2 == (short)0xdead) {
				handleReset();
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			}
			break;
		case LIST_INS: // list
			if(p1p2 == 0x0000) {
				sendLen = handleList(buf);
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			}
			break;
		case CALCULATE_INS: // calculate
			if(p1 == 0x00 && (p2 == 0x00 || p2 == 0x01)) {
				sendLen = handleCalc(buf, p2);
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			}
			break;
		case VALIDATE_INS: // validate code
			if(p1p2 == 0x0000) {
				sendLen = handleValidate(buf);
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			}
			break;
		case CALCULATE_ALL_INS: // calculate all codes
			if(p1 == 0x00 && (p2 == 0x00 || p2 == 0x01)) {
				sendLen = handleCalcAll(buf, p2);
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			}
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
		
		if(sendLen > 0) {
			apdu.setOutgoingAndSend(_0 , sendLen);
		}
	}

	private void handleReset() {
		authObj.setActive(false);
		OathObj.firstObject = null;
		OathObj.lastObject = null;
		Util.arrayFillNonAtomic(authState, _0, (short) 2, (byte)0);
		JCSystem.requestObjectDeletion();
	}

	private short handleValidate(byte[] buf) {
		if(!authObj.isActive()) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		short offs = 5;
		if(buf[offs++] != RESPONSE_TAG) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		short len = getLength(buf, offs);
		// make sure we're getting as long input as we expect
		if(len != authObj.getDigestLength()) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		offs += getLengthBytes(len);

		if(Util.arrayCompare(buf, offs, tempBuf, _0, len) == 0) {
			authState[1] = 1;
		} else {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		offs += len;
		if(buf[offs++] != CHALLENGE_TAG) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}

		len = getLength(buf, offs);
		// don't accept a challenge shorter than 8 bytes
		if(len < 8) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		offs += getLengthBytes(len);
		short respLen =  authObj.calculate(buf, offs, len, tempBuf, _0);
		buf[0] = RESPONSE_TAG;
		buf[1] = (byte) respLen;
		Util.arrayCopyNonAtomic(tempBuf, _0, buf, (short) 2, respLen);
		return (short) (respLen + 2);
	}

	private void handleChangeCode(byte[] buf) {
		short offs = 5;
		if(buf[offs++] != KEY_TAG) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		short len = getLength(buf, offs);
		offs += getLengthBytes(len);
		if(len == 0) {
			authObj.setActive(false);
		} else {
			byte type = buf[offs++];
			scratchAuth.setKey(buf, offs, type, (short) (len - 1));
			offs += (short)(len - 1);
			
			if(buf[offs++] != CHALLENGE_TAG) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			}
			len = getLength(buf, offs);
			offs += getLengthBytes(len);
			short respLen = scratchAuth.calculate(buf, offs, len, tempBuf, _0);
			offs += len;
			if(buf[offs++] != RESPONSE_TAG) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			}
			len = getLength(buf, offs);
			offs += getLengthBytes(len);
			if(len != respLen) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			}
			if(Util.arrayCompare(buf, offs, tempBuf, _0, len) == 0) {
				OathObj oldAuth = authObj;
				authObj = scratchAuth;
				scratchAuth = oldAuth;
				oldAuth.setActive(false);
				authObj.setActive(true);
			} else {
				ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			}
		}
	}

	private short handleCalc(byte[] buf, byte p2) {
		short offs = 5;
		if(buf[offs++] != NAME_TAG) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		short len = getLength(buf, offs);
		offs += getLengthBytes(len);
		OathObj object = OathObj.findObject(buf, offs, len);
		if(object == null) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		offs += len;
		
		if(buf[offs++] != CHALLENGE_TAG) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		len = getLength(buf, offs);
		offs += getLengthBytes(len);
        short respOffs = 0;
		if(p2 == 0x00) {
			len = object.calculate(buf, offs, len, tempBuf, _0);
			buf[respOffs++] = RESPONSE_TAG;
		} else {
			len = object.calculateTruncated(buf, offs, len, tempBuf, _0);
			buf[respOffs++] = T_RESPONSE_TAG;
		}
		
		respOffs += setLength(buf, respOffs, (short) (len + 1));
		buf[respOffs++] = object.getDigits();
		Util.arrayCopy(tempBuf, _0, buf, respOffs, len);
		
		return (short) (len + getLengthBytes(len) + 2);
	}
	
	private short handleCalcAll(byte[] buf, byte p2) {
		short offs = 5;
		if(buf[offs++] != CHALLENGE_TAG) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		short chalLen = getLength(buf, offs++);
		Util.arrayCopyNonAtomic(buf, offs, tempBuf, _0, chalLen);

		offs = 0;
		OathObj obj = OathObj.firstObject;
		while(obj != null) {
			if(!obj.isActive()) {
				obj = obj.nextObject;
				continue;
			}
			buf[offs++] = NAME_TAG;
			buf[offs++] = (byte) obj.getNameLength();
			offs += obj.getName(buf, offs);
			short len = 0;
			if((obj.getType() & OathObj.OATH_MASK) == OathObj.TOTP_TYPE) {
				if(p2 == 0x00) {
					buf[offs++] = RESPONSE_TAG;
					len = obj.calculate(tempBuf, _0, chalLen, buf, (short) (offs + 2));
				} else {
					buf[offs++] = T_RESPONSE_TAG;
					len = obj.calculateTruncated(tempBuf, _0, chalLen, buf, (short) (offs + 2));
				}
			} else {

				buf[offs++] = NO_RESPONSE_TAG;
			}
			buf[offs++] = (byte) (len + 1);
			buf[offs++] = obj.getDigits();
			offs += len;
			obj = obj.nextObject;
		}
		return offs;
	}

	private short handleList(byte[] buf) {
		short len = 0;
		OathObj object = OathObj.firstObject;
		while(object != null) {
			if(!object.isActive()) {
				object = object.nextObject;
				continue;
			}
			tempBuf[len++] = object.getType();
			len += setLength(tempBuf, len, object.getNameLength());
			len += object.getName(tempBuf, len);
			object = object.nextObject;
		}
		
		short offs = 0;
		buf[offs++] = NAME_LIST_TAG;
		offs += setLength(buf, offs, len);
		return Util.arrayCopy(tempBuf, _0, buf, offs, len);
	}

	private void handleDelete(byte[] buf) {
		short offs = ISO7816.OFFSET_CDATA;
		if(buf[offs++] != NAME_TAG) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		short len = getLength(buf, offs);
		offs += getLengthBytes(len);
		OathObj object = OathObj.findObject(buf, offs, len);
		if(object != null) {
			object.setActive(false);
		} else {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
	}

	private void handlePut(byte[] buf) {
		short offs = ISO7816.OFFSET_CDATA;
		if(buf[offs++] != NAME_TAG) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		short len = getLength(buf, offs);
		offs += getLengthBytes(len);
		OathObj object = OathObj.findObject(buf, offs, len);
		if(object == null) {
			object = OathObj.getFreeObject();
			object.setName(buf, offs, len);
		}
		offs += len;
		
		if(buf[offs++] != KEY_TAG) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		len = getLength(buf, offs);
		offs += getLengthBytes(len);
		
		byte keyType = buf[offs++];
		if((keyType & OathObj.HMAC_MASK) != OathObj.HMAC_SHA1 && (keyType & OathObj.HMAC_MASK) != OathObj.HMAC_SHA256) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		if((keyType & OathObj.OATH_MASK) != OathObj.TOTP_TYPE && (keyType & OathObj.OATH_MASK) != OathObj.HOTP_TYPE) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		byte digits = buf[offs++];
		
		// protect against tearing (we want to do this as late as possible)
		object.setActive(false);
		object.setDigits(digits);

		object.setKey(buf, offs, keyType, (short) (len - 2));
		offs += (short)(len - 2);
		
		if(offs < buf.length && buf[offs++] == PROPERTY_TAG) {
			object.setProp(buf[offs]);
		} else {
			object.setProp((byte) 0);
		}
		object.setActive(true);
	}
	
	private short getLength(byte[] buf, short offs) {
		short length = 0;
		if(buf[offs] <= 0x7f) {
			length = buf[offs];
		} else if(buf[offs] == (byte)0x81) {
			length = buf[(short)(offs + 1)];
		} else if(buf[offs] == (byte)0x82) {
			length = Util.getShort(buf, (short) (offs + 1));
		} else {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		return length;
	}
	
	private short getLengthBytes(short len) {
		if(len < (short)0x0080) {
			return 1;
		} else if(len <= (short)0x00ff) {
			return 2;
		} else {
			return 3;
		}
	}
	
	private short setLength(byte[] buf, short offs, short len) {
		if(len < (short)0x0080) {
			buf[offs] = (byte) len;
			return 1;
		} else if(len <= (short)0x00ff) {
			buf[offs++] = (byte)0x81;
			buf[offs] = (byte) len;
			return 2;
		} else {
			buf[offs++] = (byte)0x82;
			Util.setShort(buf, offs, len);
			return 3;
		}
	}
}
