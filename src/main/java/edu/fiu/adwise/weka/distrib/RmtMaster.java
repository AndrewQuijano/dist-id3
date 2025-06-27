package edu.fiu.adwise.weka.distrib;

import java.security.*;
import java.math.*;
import java.rmi.*;
import java.util.*;

import weka.core.Instance;

// This class also has the class attribute!!!
interface RmtMaster extends Remote {
    void linkMe(int nhosts, String[] hosts, KeyedInstances data, BigInteger p, int
            bitlength) throws RemoteException, NoSuchAlgorithmException;

    String buildClassifier(String token) throws RemoteException;

    double classifyInstance(Instance inst, String token) throws
            RemoteException;

    double[] distributionForInstance(Instance instance, String token) throws Exception;

    double locallyClassifyInstance(Instance inst, String token) throws
            RemoteException;

    double[] localDistributionForInstance(Instance inst, String token) throws RemoteException;

    BigInteger sendOn(BigInteger ciphertext, int nhosts, int cip_blk_size)
            throws RemoteException, NoSuchAlgorithmException;

    BigInteger encryptMe(BigInteger msg) throws RemoteException;

    BigInteger returnEncDisguisedNumAttr() throws RemoteException;

    double attribMaxInfoGain() throws RemoteException;

    void locallyBuildClassifier(String token) throws RemoteException;

    void prepareTransVector() throws RemoteException;

    void prepareTransVectorWithClassFilter(int index) throws
            RemoteException;

    void prepareNumAttributes(DensePublicKey pubkey) throws RemoteException;

    void prepareSet() throws RemoteException;

    int SetIntersect() throws RemoteException;

    void EncryptAndSendOn(Set<BigInteger> in_set, int nhosts, int destSite) throws RemoteException;

    void TransferLocalSet(int siteNum) throws RemoteException;

    void returningSet(Set<BigInteger> fin_set, int sourceSiteNum) throws RemoteException;

    String updateToken(int siteNum, String token) throws RemoteException;
}
