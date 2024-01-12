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
import java.lang.Exception;

public class DistribInstance extends Instance {

  protected String m_key;
  protected int m_nhosts;
  protected String m_hosts[];

  /**
   * Constructor that inititalizes instance variable with given
   * values. 
   *
   * @param key the identifying key for this instance
   * @param nhosts the number of hosts over which the instance is distributed
   * @param hosts the list of the hosts in correct order
   */
  public DistribInstance(String key, int nhosts, String hosts[]) {
    m_key = new String(key);
    m_nhosts = nhosts;
    m_hosts = hosts;
  }

  /**
   * Constructor that copies the number of hosts and the hostnames from
   * the given instance. A new key is given.
   *
   * @param key the identifying key for this instance
   * @param inst the instance from which the data is to be copied
   * @exception Exception if class is uninitialized or another instance
   * identifying to same key is already present
   */
  public DistribInstance(String key, DistribInstance inst) throws Exception{
    super(inst);
    m_key = new String(key);
    m_nhosts = inst.m_nhosts;
    m_hosts = inst.m_hosts;
  }

  /**
   * Produces a shallow copy of this instance. The copy has
   * access to the same dataset. (if you want to make a copy
   * that doesn't have access to the dataset, use 
   * <code>new UniqueInstance(key, instance)</code>
   *
   * @param key the identifying key of the new instance
   * @return the shallow copy
   * @exception Exception if class is uninitialized or another instance
   * identifying to same key is already present
   */
  /*public Object copy(String key) throws Exception {
    UniqueInstance result = new UniqueInstance(key, this);
    result.m_Dataset = m_Dataset;
    return result;
  }*/

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
  /*public UniqueInstance(String key, double weight, double[] attValues) throws
	  Exception {
	  super(weight, attValues);
	  genericInit(key);
  }
  */
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
  /*public UniqueInstance(String key, int numAttributes) throws Exception {
	  super(numAttributes);
	  genericInit(key);
  }*/


  /**
   * @return the identifying key of this instance
   */
  public String getKey() {
    return m_key;
  }

}
