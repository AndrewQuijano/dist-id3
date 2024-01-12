package weka.distrib;

import java.io.*;
import java.security.*;
import javax.crypto.*;
import sun.misc.*;
import java.math.*;
import java.rmi.*;
import java.util.*;
import weka.core.Instance;

// This class also has the class attribute!!!
public interface RmtMaster extends Remote {
  void linkMe(int nhosts, String hosts[], KeyedInstances data, BigInteger p, int
bitlength) throws RemoteException, NoSuchAlgorithmException;

  public String buildClassifier(String token) throws RemoteException;

  public double classifyInstance(Instance inst, String token) throws
    RemoteException;

  public double[] distributionForInstance(Instance instance, String token ) throws Exception;

  public double locallyClassifyInstance(Instance inst, String token) throws
  RemoteException;

  public double[] localDistributionForInstance(Instance inst, String token) throws RemoteException;

  public BigInteger sendOn(BigInteger ciphertext, int nhosts, int cip_blk_size)
    throws RemoteException,NoSuchAlgorithmException;

  public BigInteger encryptMe(BigInteger msg) throws RemoteException;

  public BigInteger returnEncDisguisedNumAttr() throws RemoteException;

  public double attribMaxInfoGain() throws RemoteException;

  public void locallyBuildClassifier(String token) throws RemoteException;

  public void prepareTransVector() throws RemoteException;

  public void prepareTransVectorWithClassFilter(int index) throws
    RemoteException;

  public void prepareNumAttributes(DensePublicKey pubkey) throws RemoteException;

  public void prepareSet() throws RemoteException;

  public int SetIntersect() throws RemoteException;

  public void EncryptAndSendOn(Set in_set, int nhosts, int destSite) throws RemoteException;

  public void TransferLocalSet(int siteNum) throws RemoteException;

  public void returningSet(Set fin_set, int sourceSiteNum) throws RemoteException;

  public String updateToken(int siteNum, String token) throws RemoteException;
}
