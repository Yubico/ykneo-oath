package pkgYkneoOath;

/*
 * Copyright (c) 2013 Yubico AB
 * All rights reserved.
 */

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.RandomData;

public class YkneoOath extends Applet {
	
	private static final short _0 = 0;

	private static final byte CHALLENGE_LENGTH = 8;
	
	private byte[] tempBuf;

	private OathObj authObj;
	private byte[] authState;
	
	private RandomData rng;
	
	private byte[] identity;

	public YkneoOath() {
		tempBuf = JCSystem.makeTransientByteArray((short) 512, JCSystem.CLEAR_ON_DESELECT);
		authState = JCSystem.makeTransientByteArray((short)2, JCSystem.CLEAR_ON_DESELECT);
		rng = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
		
		identity = new byte[CHALLENGE_LENGTH];
		rng.generateData(identity, _0, CHALLENGE_LENGTH);
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new YkneoOath().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	public void process(APDU apdu) {
		if (selectingApplet()) {
			byte[] buf = apdu.getBuffer();
			short offs = 0;
			buf[offs++] = 0x7a;
			short nameLen = (short) identity.length;
			buf[offs++] = (byte) nameLen;
			Util.arrayCopyNonAtomic(identity, _0, buf, offs, nameLen);
			offs += nameLen;

			// if the authobj is set add a challenge
			if(authObj != null) {
				buf[offs++] = 0x7f;
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
		
		if(authObj != null && ins != (byte)0xa3) {
			if(authState[1] != 1) {
				ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			}
		}
		
		switch (ins) {
		case (byte)0x01: // put
			if(p1p2 == 0x0000) {
				handlePut(buf);
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			}
			break;
		case (byte)0x02: // delete
			if(p1p2 == 0x0000) {
				handleDelete(buf);
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			}
			break;
		case (byte)0x03: // set code
			if(p1p2 == 0x0000) {
				handleChangeCode(buf);
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			}
			break;
		case (byte)0xa1: // list
			if(p1p2 == 0x0000) {
				sendLen = handleList(buf);
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			}
			break;
		case (byte)0xa2: // calculate
			if(p1 == 0x00 && (p2 == 0x00 || p2 == 0x01)) {
				sendLen = handleCalc(buf, p2);
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			}
			break;
		case (byte)0xa3: // validate code
			if(p1p2 == 0x0000) {
				sendLen = handleValidate(buf);
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			}
			break;
		case (byte)0xa4: // calculate all codes
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
		authObj = null;
		OathObj.firstObject = null;
		OathObj.lastObject = null;
		JCSystem.requestObjectDeletion();
	}

	private short handleValidate(byte[] buf) {
		if(authObj == null) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		short offs = 5;
		byte ins = buf[offs++];
		short len = getLength(buf, offs);
		// make sure we're getting as long input as we expect
		if(len != authObj.getDigestLength()) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		offs += getLengthBytes(len);
		if(authState[0] == 0  && ins == 0x7f) {
			if(Util.arrayCompare(buf, offs, tempBuf, _0, len) == 0) {
				authState[1] = 1;
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			}
			offs += len;
			ins = buf[offs++];
			len = getLength(buf, offs);
			// don't accept a challenge shorter than 8 bytes
			if(len < 8) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			}
			offs += getLengthBytes(len);
			short respLen =  authObj.calculate(buf, offs, len, tempBuf, _0);
			buf[0] = 0x7d;
			buf[1] = (byte) respLen;
			Util.arrayCopyNonAtomic(tempBuf, _0, buf, (short) 2, respLen);
			return (short) (respLen + 2);
		} else {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		return 0;
	}

	private void handleChangeCode(byte[] buf) {
		boolean dirty = false;
		short offs = 5;
		if(buf[offs++] != 0x7b) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		byte type = buf[offs++];
		short len = getLength(buf, offs);
		offs += getLengthBytes(len);
		if(authObj != null) {
			dirty = true;
		}
		if(len == 0) {
			authObj = null;
		} else {
			OathObj updateAuthObj = new OathObj();
			updateAuthObj.setKey(buf, offs, type, len);
			offs += len;
			
			if(buf[offs++] != 0x7c) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			}
			len = getLength(buf, offs);
			offs += getLengthBytes(len);
			short respLen = updateAuthObj.calculate(buf, offs, len, tempBuf, _0);
			offs += len;
			if(buf[offs++] != 0x7d) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			}
			len = getLength(buf, offs);
			offs += getLengthBytes(len);
			if(len != respLen) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			}
			if(Util.arrayCompare(buf, offs, tempBuf, _0, len) == 0) {
				authObj = updateAuthObj;
			} else {
				ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			}
			
			updateAuthObj = null;
		}
		if(dirty) {
			JCSystem.requestObjectDeletion();
		}
	}

	private short handleCalc(byte[] buf, byte p2) {
		short offs = 5;
		if(buf[offs++] != 0x7a) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		short len = getLength(buf, offs);
		offs += getLengthBytes(len);
		OathObj object = OathObj.findObject(buf, offs, len);
		if(object == null) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		offs += len;
		
		if(buf[offs++] != 0x7d) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		len = getLength(buf, offs);
		offs += getLengthBytes(len);
		if(p2 == 0x00) {
			len = object.calculate(buf, offs, len, tempBuf, _0);
		} else {
			len = object.calculateTruncated(buf, offs, len, tempBuf, _0);
		}
		
		offs = 0;
		buf[offs++] = 0x7d;
		offs += setLength(buf, offs, len);
		Util.arrayCopy(tempBuf, _0, buf, offs, len);
		
		return (short) (len + getLengthBytes(len) + 1);
	}
	
	private short handleCalcAll(byte[] buf, byte p2) {
		short offs = 5;
		if(buf[offs++] != 0x7d) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		short chalLen = getLength(buf, offs++);
		Util.arrayCopyNonAtomic(buf, offs, tempBuf, _0, chalLen);

		offs = 0;
		OathObj obj = OathObj.firstObject;
		while(obj != null) {
			buf[offs++] = 0x7a;
			buf[offs++] = (byte) obj.getNameLength();
			offs += obj.getName(buf, offs);
			buf[offs++] = 0x7d;
			short len;
			if(p2 == 0x00) {
				len = obj.calculate(tempBuf, _0, chalLen, buf, (short) (offs + 1));
			} else {
				len = obj.calculateTruncated(tempBuf, _0, chalLen, buf, (short) (offs + 1));
			}
			buf[offs++] = (byte) len;
			offs += len;
			obj = obj.nextObject;
		}
		return offs;
	}

	private short handleList(byte[] buf) {
		short len = 0;
		OathObj object = OathObj.firstObject;
		while(object != null) {
			tempBuf[len++] = object.type;
			len += setLength(tempBuf, len, object.getNameLength());
			len += object.getName(tempBuf, len);
			object = object.nextObject;
		}
		
		short offs = 0;
		buf[offs++] = (byte) 0xa1;
		offs += setLength(buf, offs, len);
		return Util.arrayCopy(tempBuf, _0, buf, offs, len);
	}

	private void handleDelete(byte[] buf) {
		short offs = ISO7816.OFFSET_CDATA;
		if(buf[offs++] != 0x7a) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		short len = getLength(buf, offs);
		offs += getLengthBytes(len);
		OathObj object = OathObj.findObject(buf, offs, len);
		if(object != null) {
			object.removeObject();
			JCSystem.requestObjectDeletion();
		} else {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
	}

	private void handlePut(byte[] buf) {
		short offs = ISO7816.OFFSET_CDATA;
		if(buf[offs++] != 0x7a) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		short len = getLength(buf, offs);
		offs += getLengthBytes(len);
		OathObj object = OathObj.findObject(buf, offs, len);
		if(object == null) {
			object = new OathObj();
			object.setName(buf, offs, len);
		} else {
			// make sure we protect against tearing
			object.removeObject();
		}
		offs += len;
		
		if(buf[offs++] != 0x7b) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		byte keyType = buf[offs++];
		if(keyType != OathObj.HMAC_SHA1 && keyType != OathObj.HMAC_SHA256) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		len = getLength(buf, offs);
		offs += getLengthBytes(len);
		object.setKey(buf, offs, keyType, len);
		offs += len;
		
		if(offs < buf.length && buf[offs++] == 0x7c) {
			object.setProp(buf[offs]);
		} else {
			object.setProp((byte) 0);
		}
		
		object.addObject();
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
