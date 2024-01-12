/*
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program; if not, write to the Free Software
 *    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 *    IndividualInstance.java
 *    Copyright (C) 2003 Peter A. Flach, Nicolas Lachiche
 *
 */

package weka.distrib;
import java.util.Hashtable;

public class HashTableMap implements MapObject {
	Hashtable objects;

	HashTableMap() {
		objects = new Hashtable();
	}

	/**
	 * @param key key of the object to retrieve
	 */
	public Object get(String key) {
		return objects.get(key);
	}

	/**
	 * @param key key of the object
	 * @param obj the object to store
	 */
	public void set(String key, Object obj) {
		objects.put(key, obj);
	}
}
