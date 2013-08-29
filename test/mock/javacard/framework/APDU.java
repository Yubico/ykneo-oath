package javacard.framework;

import java.util.Arrays;

public class APDU {
	byte[] buffer;
	
	public APDU(byte[] buf) {
		buffer = buf;
	}
	
    public byte[] getBuffer() {
    	return buffer;
    }
    
    public short setIncomingAndReceive() {
        return (short) buffer.length;
    }
    
    public void setOutgoingAndSend(short bOff, short len) {
    	Arrays.fill(buffer, bOff + len, buffer.length, (byte)0);
    }
}
