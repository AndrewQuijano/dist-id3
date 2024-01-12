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

import weka.core.Instance;
import weka.core.Attribute;
import java.lang.Exception;

public class KeyedInstance extends Instance {

  private static MapObject g_allInstances = null;

  // For now, use a simple HashTableMap for the MapObject
/*
  static{
	  g_allInstances = new HashTableMap();
  }

  public static void setMap(MapObject map) {
	  g_allInstances = map;
  }

  private void genericInit(String key) throws Exception {
	  if (g_allInstances == null)
		  throw new Exception("Class not initialized yet");

	  KeyedInstance result = (KeyedInstance)g_allInstances.get(key);
	  if (result != null)
		  throw new Exception("Key is already defined");

	  g_allInstances.set(key, this);
	  m_key = new Instance(1);
	  m_key = key;
  }
*/

  /**
   * Constructor that copies the attribute values and the weight from
   * the given instance. Reference to the dataset is set to null.
   * (ie. the instance doesn't have access to information about the
   * attribute types)
   *
   * @param instance the instance from which the attribute
   * values and the weight are to be copied 
   * @exception Exception if class is uninitialized or another instance
   * identifying to same key is already present
   */
  public KeyedInstance(KeyedInstance inst) throws Exception{
	  super(inst);
  }

  /**
   * Constructor that copies the attribute values and the weight from
   * the given instance. Reference to the dataset is set to null.
   * (ie. the instance doesn't have access to information about the
   * attribute types)
   *
   * @param instance the instance from which the attribute
   * values and the weight are to be copied 
   * @exception Exception if class is uninitialized or another instance
   * identifying to same key is already present
   */
  public KeyedInstance(Instance inst) throws Exception{
	  super(inst);
  }

  /**
   * Constructor that copies the attribute values and the weight from
   * the given instance. Reference to the dataset is set to null.
   * (ie. the instance doesn't have access to information about the
   * attribute types)
   *
   * @param key the key of the new instance
   * @param inst the instance from which the attribute
   * values and the weight are to be copied 
   * @exception Exception if class is uninitialized or another instance
   * identifying to same key is already present
   */
  public KeyedInstance(String key, KeyedInstance inst) throws Exception{
    super(inst);
    for (int i=0; i <numAttributes(); i++) {
      Attribute attr = attribute(i);
      if (attr.name().equals("_keyAttr") == true) {
	setValue(attribute(0),key);
	break;
      }
    }
  }


  /**
   * Produces a shallow copy of this instance. The copy has
   * access to the same dataset. (if you want to make a copy
   * that doesn't have access to the dataset, use 
   * <code>new KeyedInstance(key, instance)</code>
   *
   * @param key the identifying key of the new instance
   * @return the shallow copy
   * @exception Exception if class is uninitialized or another instance
   * identifying to same key is already present
   */
  public Object copy(String key) throws Exception {
    KeyedInstance result = new KeyedInstance(key, this);
    result.m_Dataset = m_Dataset;
    return result;
  }

  /**
   * Constructor that inititalizes instance variable with given
   * values. Reference to the dataset is set to null. (ie. the instance
   * doesn't have access to information about the attribute types)
   *
   * @param key the identifying key for this instance
   * @param weight the instance's weight
   * @param attValues a vector of attribute values 
   * @exception Exception if class is uninitialized or another instance
   * identifying to same key is already present
   */
  public KeyedInstance(String key, double weight, double[] attValues) throws
	  Exception {
	  super(weight, attValues);
	  //genericInit(key);
  }

  /**
   * Constructor of an instance that sets weight to one, all values to
   * be missing, and the reference to the dataset to null. (ie. the instance
   * doesn't have access to information about the attribute types)
   *
   * @param key the identifying key for this instance
   * @param numAttributes the size of the instance 
   * @exception Exception if class is uninitialized or another instance
   * identifying to same key is already present
   */
  public KeyedInstance(String key, int numAttributes) throws Exception {
	  super(numAttributes);
	  //genericInit(key);
  }

}
