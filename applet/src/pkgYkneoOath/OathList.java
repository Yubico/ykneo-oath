package pkgYkneoOath;

/*
 * Copyright (c) 2014 Fidesmo AB
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

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;

public class OathList {

	private static final short _0 = 0;

	public OathObj firstObject;
	public OathObj lastObject;

	// keep temporary buffers for all nodes in a central location, but safe from other applets
	MessageDigest sha;
	MessageDigest sha256;
	byte[] scratchBuf;

	public OathList() {
		scratchBuf = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
	}

	public OathObj getFreeObject() {
		OathObj object;
		for(object = firstObject; object != null; object = object.nextObject) {
			if(!object.isActive()) {
				break;
			}
		}
		if(object == null) {
			object = new OathObj(this);
			object.addObject();
		}
		return object;
	}

	public OathObj findObject(byte[] name, short offs, short len) {
		OathObj object;
		for(object = firstObject; object != null; object = object.nextObject) {
			if(!object.isActive() || len != object.getNameLength()) {
				continue;
			}

			if(object.nameEquals(name, offs)) {
				break;
			}
		}
		return object;
	}

}
