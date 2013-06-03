package javacard.framework;

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
    	
    }
}
