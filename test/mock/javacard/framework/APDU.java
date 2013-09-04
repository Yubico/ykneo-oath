package javacard.framework;

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
    
    public static short getOutBlockSize() {
        return (short)0x00ff;
    }
}
