package weka.distrib;

import java.io.*;
import java.security.*;
import javax.crypto.*;
import sun.misc.*;
import java.math.*;
 import java.rmi.*;
import java.util.*;
import weka.core.Instance;

public interface RmtStart extends Remote {
  public void buildClassifier() throws Exception;
  public double classifyInstance(Instance instance) throws Exception;
  public double[] distributionForInstance(Instance instance) throws Exception;
}
