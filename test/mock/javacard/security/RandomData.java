package javacard.security;

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

import java.util.Random;

public class RandomData {
	public static final RandomData getInstance(byte algorithm) {
		return new RandomData();
	}
	
	public void generateData(byte[] buffer, short offset, short length) {
		Random r = new Random();
		
		for(int i = 0; i < length; i++) {
			buffer[offset + i] = (byte) r.nextInt();
		}
	}
}
