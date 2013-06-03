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
import javacard.framework.OwnerPIN;
import javacard.framework.Util;

public class YkneoOath extends Applet {
	
	private static final short _0 = 0;
	
	private byte[] tempBuf;
	
	private OwnerPIN lockCode;

	public YkneoOath() {
		tempBuf = JCSystem.makeTransientByteArray((short) 512, JCSystem.CLEAR_ON_DESELECT);
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new YkneoOath().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	public void process(APDU apdu) {
		if (selectingApplet()) {
			return;
		}

		byte[] buf = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		short sendLen = 0;
		
		byte p1 = buf[ISO7816.OFFSET_P1];
		byte p2 = buf[ISO7816.OFFSET_P2];
		short p1p2 = Util.makeShort(p1, p2);
		byte ins = buf[ISO7816.OFFSET_INS];
		
		if(lockCode != null && ins != (byte)0xa3) {
			// if the lockCode is blocked we allow reset by ins ff
			if(lockCode.getTriesRemaining() == 0 && ins == (byte)0xff) {
				handleReset();
				return;
			}
			if(!lockCode.isValidated()) {
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
			if(p1p2 == 0x0000) {
				sendLen = handleCalc(buf);
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			}
			break;
		case (byte)0xa3: // validate code
			if(p1p2 == 0x0000) {
				handleValidate(buf);
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
		lockCode = null;
		OathObj.firstObject = null;
		OathObj.lastObject = null;
		JCSystem.requestObjectDeletion();
	}

	private void handleValidate(byte[] buf) {
		short offs = 5;
		if(buf[offs++] != 0x7e) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		short len = getLength(buf, offs++);
		if(len == 0 || len > 32) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		if(lockCode != null) {
			if(!lockCode.check(buf, offs, (byte) len)) {
				ISOException.throwIt((short) (0x6300 + lockCode.getTriesRemaining()));
			}
		}
	}

	private void handleChangeCode(byte[] buf) {
		short offs = 5;
		if(buf[offs++] != 0x7e) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		short len = getLength(buf, offs++);
		if(len == 0) {
			lockCode = null;
			JCSystem.requestObjectDeletion();
		} else {
			if(len > 32) {
				ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			}
			if(lockCode == null) {
				lockCode = new OwnerPIN((byte) 10, (byte)32);
			}
			lockCode.update(buf, offs, (byte) len);
		}
	}

	private short handleCalc(byte[] buf) {
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
		len = object.calculate(buf, offs, len, tempBuf, _0);
		
		offs = 0;
		buf[offs++] = 0x7d;
		offs += setLength(buf, offs, len);
		Util.arrayCopy(tempBuf, _0, buf, offs, len);
		
		return (short) (len + getLengthBytes(len) + 1);
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
		
		if(buf[offs++] == 0x7c) {
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
			length = buf[offs + 1];
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
