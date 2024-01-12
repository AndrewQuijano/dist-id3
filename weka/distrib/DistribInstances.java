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

import weka.core.Instances;
import weka.core.Attribute;
import weka.core.*;
import java.io.*;
import java.lang.Exception;

public class DistribInstances extends Instances {

  private static MapObject g_instanceRegistry = null;
    
  // For now, use a simple HashTableMap for the MapObject
  static{
    g_instanceRegistry = new HashTableMap();
  }
                 
  public static void setMap(MapObject map) {
    g_instanceRegistry = map;
  }

  private void genericInit() throws IOException {
    Attribute keyattr = attribute("_keyAttr");
    if (keyattr == null) {
      throw new IOException();
      //throw new KeyAttributeNotFoundException();
    }
  }

  private void registerInstance(KeyedInstance inst) {
    Attribute keyattr = attribute("_keyAttr");
    String key = inst.stringValue(keyattr);
    //assert(key != null);
    g_instanceRegistry.set(key, inst);
  }

  /**
   * Reads an ARFF file from a reader, and assigns a weight of
   * one to each instance. Lets the index of the class 
   * attribute be undefined (negative).
   *
   * @param reader the reader
   * @exception IOException if the ARFF file is not read 
   * successfully
   */
  public DistribInstances(Reader reader) throws IOException {
    super(reader);

    genericInit();
  }
 
  /**
   * Reads the header of an ARFF file from a reader and 
   * reserves space for the given number of instances. Lets
   * the class index be undefined (negative).
   *
   * @param reader the reader
   * @param capacity the capacity
   * @exception IllegalArgumentException if the header is not read successfully
   * or the capacity is negative.
   * @exception IOException if there is a problem with the reader.
   */
   public DistribInstances(Reader reader, int capacity) throws IOException {
     super(reader, capacity);

     genericInit();
  }

  /**
   * Constructor copying all instances and references to
   * the header information from the given set of instances.
   *
   * @param instances the set to be copied
   */
  public DistribInstances(DistribInstances dataset) throws IOException {
    super(dataset);

    genericInit();
  }

  /**
   * Constructor creating an empty set of instances. Copies references
   * to the header information from the given set of instances. Sets
   * the capacity of the set of instances to 0 if its negative.
   *
   * @param instances the instances from which the header 
   * information is to be taken
   * @param capacity the capacity of the new dataset 
   */
  public DistribInstances(Instances dataset, int capacity) throws IOException{
    super(dataset, capacity);

    genericInit();
  }

  /**
   * Creates a new set of instances by copying a 
   * subset of another set.
   *
   * @param source the set of instances from which a subset 
   * is to be created
   * @param first the index of the first instance to be copied
   * @param toCopy the number of instances to be copied
   * @exception IllegalArgumentException if first and toCopy are out of range
   */
  public DistribInstances(DistribInstances source, int first, int toCopy) throws
    Exception{
    super(source, first, toCopy);

    genericInit();
  }

  /**
   * Creates an empty set of instances. Uses the given
   * attribute information. Sets the capacity of the set of 
   * instances to 0 if its negative. Given attribute information
   * must not be changed after this constructor has been used.
   *
   * @param name the name of the relation
   * @param attInfo the attribute information
   * @param capacity the capacity of the set
   */
  public DistribInstances(String name, FastVector attInfo, int capacity) throws
    IOException {
    super(name, attInfo, capacity);

    genericInit();
  }

  /**
   * Adds one instance to the end of the set. 
   * Shallow copies instance before it is added. Increases the
   * size of the dataset if it is not large enough. Does not
   * check if the instance is compatible with the dataset.
   *
   * @param inst the instance to be added
   */
  public final void add(KeyedInstance inst) {
    super.add(inst);
    registerInstance(inst);
  }

  public static void main(String args[]) {
    //DistribInstances uinsts2 = null;
    //Instances insts = new Instances(uinsts2);
    //DistribInstances uinsts1 = new DistribInstances(uinsts2);
  }
}
