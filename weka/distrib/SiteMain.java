package weka.distrib;

import java.rmi.*;
import java.util.*;

import java.io.*;
import java.security.*;
import javax.crypto.*;
import sun.misc.*;
import java.math.*;
import weka.core.Instance;

public class SiteMain extends java.rmi.server.UnicastRemoteObject implements RmtStart {

  boolean m_ClassifierBuilt = false;
  int m_nhosts;
  String m_hosts[];
  RmtMaster m_Master;
  RmtSlave m_Slaves[];
  KeyedInstances m_data;
  static final int g_bitLength = 500;
  static long g_seed;
  boolean debug = true;
    
    /*Alice()throws RemoteException { }*/

  SiteMain(KeyedInstances data, int nSites, String hosts[]) throws java.rmi.RemoteException {
    /*
    m_nhosts = data.numAttributes() - 1;
    m_hosts = new String[m_nhosts];
    Instance inst = data.firstInstance();
    for (int i=0; i<m_nhosts; i++) {
      m_hosts[i] = inst.stringValue(i+1);
      System.out.println("Host is " + m_hosts[i]);
    }*/
    m_nhosts = nSites;
    m_hosts = hosts;
    m_data = data;
  }

  public void buildClassifier() throws Exception {
    m_ClassifierBuilt = true;
    bindMaster(0);
    bindSlaves(0);
    linkAllSites(m_data);
    m_Master.buildClassifier("");
    if (debug) {
      System.out.println("Classifier has been built");
    }
  }

  public double classifyInstance(Instance instance) throws Exception {
    if (m_ClassifierBuilt == false) {
      return -1;
    }

    return m_Master.classifyInstance(instance, "");
  }

  /**
   * Computes class distribution for instance using decision tree.
   *
   * @param instance the instance for which distribution is to be computed
   * @return the class distribution for the given instance
   */
  public double[] distributionForInstance(Instance instance) throws
    Exception {
    return m_Master.distributionForInstance(instance, "");
  }

  private void bindMaster(int show) {
    try {
      if (show != 0)
	System.out.println("rmi://"+m_hosts[0]+"/Site1");

      m_Master = (RmtMaster)Naming.lookup("rmi://"+m_hosts[0]+"/Site1");
    } catch (java.io.IOException e){
      System.out.println("IO Error or bad URL");
    } catch (NotBoundException e){
      System.out.println("Server Not Registered");
    }
  }

  private void bindSlaves(int show) {
    m_Slaves = new RmtSlave[m_nhosts-1];
    try {
      for (int i=1; i<m_nhosts; i++) {
	String lookupSite = new String("rmi://"+m_hosts[i]+"/Site"+(i+1));
        if (show != 0)
	  System.out.println(lookupSite);

        m_Slaves[i-1] =
	  (RmtSlave)Naming.lookup(lookupSite);
      }
    } catch (java.io.IOException e){
      System.out.println("IO Error or bad URL");
    } catch (NotBoundException e){
      System.out.println("Server Not Registered");
    }
  }

  private void linkAllSites(KeyedInstances data) throws Exception {
    Random rnd = SecureRandom.getInstance("SHA1PRNG");
    Date d = new Date();
    SiteMain.g_seed = d.getTime();
    rnd.setSeed(g_seed);
    BigInteger m_p = BigInteger.probablePrime(g_bitLength, rnd);
    m_Master.linkMe(m_nhosts, m_hosts, data, m_p, g_bitLength);
    for (int i=1; i<m_nhosts;  i++) {
      m_Slaves[i-1].linkMe(m_nhosts, m_hosts, data, m_p, g_bitLength);
    }
  }

}
