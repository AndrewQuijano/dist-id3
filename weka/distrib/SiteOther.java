package weka.distrib;

import java.rmi.*;
import java.util.*;

import java.io.*;
import java.security.*;
import javax.crypto.*;
import sun.misc.*;
import java.math.BigInteger;
import javax.crypto.spec.*;
import weka.core.*;
import java.lang.reflect.Array;

public class SiteOther
    extends java.rmi.server.UnicastRemoteObject
    implements RmtSlave {

      boolean debug = false;
  /** The number of sites */
  int m_nhosts;

  /** The link to the master */
  RmtMaster m_Master;

  /** The link to the slaves */
  RmtSlave m_Slaves[];

  /** The keys for data */
  KeyedInstances m_data;

  /** The number of this site */
  int m_siteNum;

  /** The global copy of the local instances */
  static KeyedInstances g_insts;

  /** The local copy of the instances */
  KeyedInstances m_insts;

  /** The global copy of the universe of test instances */
  static KeyedInstances g_test_insts;

  /** Hashtable with map of instances to keys */
  static Hashtable g_instHashtbl;

  /** The number of attributes in the instances */
  int m_nAtt;

  /** The number of classes. (This is the only private info of the class site
   * which is known to any other site */
  int m_numClasses;

  /** The temporary ciphertext for num attributes protocol*/
  BigInteger m_ciphertext;

  /** The common modulus p for Pohlig-Hellman */
  BigInteger m_p;

  /** The Pohlig-Hellman object with common p */
  PohligHellman m_phellman;

  /** The Benaloh Dense Cipher object */
  DenseCipher m_localcyp;

  /** The Benaloh Dense Cipher object sent by other sites */
  DenseCipher m_othercyp;

  /** The Benaloh Dense Cipher key generation object */
  Dense m_hmorphkeys;

  /** The secret random kept for finding out if number of atts is 0 */
  BigInteger m_sendOnRand;

  /** The classification table */
  protected Hashtable m_classificationTbl;

  /** Local stack which helps simulate the global stack */
  Stack m_requirementStack;

  /** Local stack which helps simulate the global stack for attributes */
  Stack m_attributeStack;

  /** The classifying attribute stack */
  private Stack m_currClassAttrInfoStack;

  /** Class value if node is leaf. */
  private double m_ClassValue;

  /** Class distribution if node is leaf. */
  private double[] m_Distribution;

  /** The current best classifying attribute. */
  private Attribute m_classifyingAttribute;

  /** The array for creating the transaction vector. Using array for efficiency
   * purposes. Could use a vector otherwise. */
  private Object m_transVector;

  /** The set used for intersection purposes */
  private Set m_set;

  /** The final encrypted sets used for intersection */
  private Set[] m_enc_sets;

  private static final int txt_blk_size = 8;
  private static final int cip_blk_size = 32;
  private static final int prec = 1;
  private static final int show = 1;

  private static final int MASTER_SITE = 1;

  SiteOther(int siteNum) throws Exception {
    m_siteNum = siteNum;
    m_insts = new KeyedInstances(g_insts);
    m_classificationTbl = new Hashtable();
    m_requirementStack = new Stack();
    m_attributeStack = new Stack();
    m_transVector = Array.newInstance(boolean.class, m_insts.numInstances());
    m_nAtt = m_insts.numAttributes() - 2; // Decrement for key attribute and the
//dummy class value required by weka...
    m_hmorphkeys = new
      Dense(SiteOther.txt_blk_size,SiteOther.cip_blk_size,SiteOther.prec,SiteOther.show);
    m_localcyp = new DenseCipher(m_hmorphkeys);
    // Could easily be smaller.. I wonder if I should use a smaller capacity
    m_set = new HashSet(m_insts.numInstances());
    m_currClassAttrInfoStack = new Stack();
  }

  /** Sets the number of classes */
  public void setNumClasses(int nclasses) throws RemoteException {
    m_numClasses = nclasses;
  }

  public void linkMe(int nhosts, String hosts[], KeyedInstances data, BigInteger
      p, int bitlength) throws RemoteException, NoSuchAlgorithmException {
    m_nhosts = nhosts;
    m_enc_sets = new Set[nhosts];
    m_p = p;
    m_data = data;
    m_phellman = new PohligHellman(p, bitlength);
    m_Slaves = new RmtSlave[m_nhosts-1];
    try {
      m_Master = (RmtMaster)Naming.lookup(new
	  String("rmi://"+hosts[0]+"/Site1"));
      for (int i=1; i<m_nhosts; i++) {
	if ((i+1) == m_siteNum) {
	  m_Slaves[i-1] = this;
	}
	else {
	  String lookupSite = new String("rmi://"+hosts[i]+"/Site"+(i+1));

	  m_Slaves[i-1] = (RmtSlave)Naming.lookup(lookupSite);
	}
      }
    } catch (java.io.IOException e){
      System.out.println("IO Error or bad URL");
    } catch (NotBoundException e){
      System.out.println("Server Not Registered");
    }
  }

  public void prepareNumAttributes(DensePublicKey pubkey ) throws
  RemoteException {
    m_othercyp = new DenseCipher(pubkey);
    prepareNumAttributes(m_othercyp);
  }

  public void prepareNumAttributes(DenseCipher cyp) throws
    RemoteException {
    int numAtt = m_nAtt - m_attributeStack.size();

    // using leq for safety. actually eq 0 should be sufficient)
    if (numAtt <= 0) {
      m_ciphertext = cyp.Encrypt(BigInteger.ZERO);
    } 
    else {
      m_ciphertext = cyp.Encrypt(BigInteger.ONE);
    }
  }

  public BigInteger sendOn(BigInteger ciphertext, int nhosts, int cip_blk_size)
  throws RemoteException,NoSuchAlgorithmException {
    BigInteger outnum = (ciphertext.multiply(m_ciphertext)).mod(m_othercyp.PubK.n);

    if (nhosts <= 1) {
      Random rnd = SecureRandom.getInstance("SHA1PRNG");
      rnd.setSeed((new Date()).getTime());
      m_sendOnRand = (new BigInteger(cip_blk_size, rnd)).mod(m_othercyp.PubK.r);
	//m_sendOnRand = new BigInteger("3");
      outnum =
	(outnum.multiply(m_othercyp.Encrypt(m_sendOnRand))).mod(m_othercyp.PubK.n);
      return outnum;
    }
    else {
      int hostNum = m_siteNum + 1;
      if (hostNum == m_nhosts+1) {
	return m_Master.sendOn(outnum, nhosts-1, cip_blk_size);
      }
      else {
	return m_Slaves[hostNum-2].sendOn(outnum, nhosts-1, cip_blk_size);
      }
    }
  }

  public BigInteger encryptMe(BigInteger msg) throws RemoteException {
    return m_phellman.Encrypt(msg);
  }

  public BigInteger returnEncDisguisedNumAttr() throws RemoteException {
    return m_phellman.Encrypt(m_sendOnRand);
  }

  // !!!
  private Instance getInstance(Instance inst) {
    // Fix this..
    // For now hardcoding key attr to be attr 0
    Attribute att = inst.attribute(0);
    return (Instance)g_instHashtbl.get(inst.stringValue(att));
  }

  private boolean isNumAttributesZero(String token) throws
    RemoteException,NoSuchAlgorithmException {
    // Basic idea is to use homomorphic encryption. You only need a vote by all
    // sides to find out if none of the sides has any attributes left
    // Use token to find out which sites have been utilized 
    // Everyone has a temp numattributes
    prepareNumAttributes(m_localcyp);
    //prepareNumAttributes(m_hmorphkeys.GetPublicKey());

    m_Master.prepareNumAttributes(m_hmorphkeys.GetPublicKey());
    for (int i=0; i<m_nhosts-1; i++) {
      if (i+2 != m_siteNum) {
	m_Slaves[i].prepareNumAttributes(m_hmorphkeys.GetPublicKey());
      }
    }

    BigInteger encr_numAttr;
    if (m_siteNum == m_nhosts) {
      encr_numAttr = m_Master.sendOn(m_ciphertext, m_nhosts - 1,
	  SiteOther.cip_blk_size);
    }
    else {
      encr_numAttr = m_Slaves[m_siteNum-1].sendOn(m_ciphertext, m_nhosts - 1,
	  SiteOther.cip_blk_size);
    }

    BigInteger disguisedNumAttr = m_localcyp.Decrypt(encr_numAttr);

    BigInteger comp1, comp2;
    if (m_siteNum == 2) {
      comp1 = m_Master.encryptMe(m_phellman.Encrypt(disguisedNumAttr));
      comp2 = m_phellman.Encrypt(m_Master.returnEncDisguisedNumAttr());
    }
    else {
      comp1 =
	m_Slaves[m_siteNum-3].encryptMe(m_phellman.Encrypt(disguisedNumAttr));
      comp2 =
	m_phellman.Encrypt(m_Slaves[m_siteNum-3].returnEncDisguisedNumAttr());
    }

    if (comp1.equals(comp2)) {
      return true;
    } else {
      return false;
    }
  }

  private TreeNode formMajorityClassLeaf(String token) throws RemoteException {
    boolean nonZeroFlag = false;
    for (int i = 1; i<m_nhosts; i++)
      m_Slaves[i-1].prepareTransVector();

    m_Distribution = new double[m_numClasses];
    for (int i=0; i<m_numClasses; i++) {
      m_Master.prepareTransVectorWithClassFilter(i);
      m_Distribution[i] = SetIntersect();
      if (m_Distribution[i] > 0) nonZeroFlag = true;
    }
    
    if (!nonZeroFlag) {
      for (int i=0; i<m_numClasses; i++) {
	m_Distribution[i] = 1;
      }
    }

    Utils.normalize(m_Distribution);
    m_ClassValue = Utils.maxIndex(m_Distribution);

    return new LeafNode(m_ClassValue, m_Distribution);
  }

  /* Should set the class guy's local variable to the appropriate class if
   * returning true because it will then be followed by a call to
   * formLeafNode()
   */
  private boolean allTransHaveSameClass(String token) throws RemoteException {
    // For efficiency reason we should stop set intersect as soon as 2 classes
    // are found to be nonzero. (Note this in the implementation). However, for
    // proof of security purposes, we can go ahead 
    int numClassesNonZero = 0;
    for (int i = 0; i<m_nhosts-1; i++)
      m_Slaves[i].prepareTransVector();

    m_Distribution = new double[m_numClasses];
    for (int i=0; i<m_numClasses; i++) {
      m_Master.prepareTransVectorWithClassFilter(i);
      m_Distribution[i] = SetIntersect();
      if (m_Distribution[i] != 0) {
	m_ClassValue = i;
	m_Distribution[i] = 1; // Effective normalizing the distribution
	if(++numClassesNonZero >= 2)
	  return false; // Clearly atleast 2 classes have non zero components
      }
    }
    
    if (numClassesNonZero == 0) {
      for (int i=0; i<m_numClasses; i++) {
	m_Distribution[i] = 1;
      }
      Utils.normalize(m_Distribution);
      m_ClassValue = Utils.maxIndex(m_Distribution);
    }

    return true;
  }

  /** This method has to create the local transaction vector based on the
   * current requirements */
  public void prepareTransVector() throws RemoteException {
    for (int i=0; i<m_insts.numInstances(); i++) {
      if (requirementsMet(m_insts.instance(i)) == true) {
	Array.setBoolean(m_transVector,i,true);
      }
      else {
	Array.setBoolean(m_transVector,i,false);
      }
    }
  }

  private boolean requirementsMet(Instance inst) {
    for (int i=0; i<m_requirementStack.size(); i++) {
      InfoObject io = (InfoObject)m_requirementStack.elementAt(i);
      String instValue = inst.stringValue(io.returnAttribute().index());
      if (instValue.equals(io.returnValue()) == false)
	return false;
    }

    return true;
  }

  public TreeNode formLeafNode(String token) {
    return new LeafNode(m_ClassValue, m_Distribution);
  }

  public double locallyClassifyInstance(Instance inst, String token) throws
  RemoteException { 
    TreeNode node = (TreeNode)m_classificationTbl.get(token);
    if (node instanceof LeafNode) {
      return ((LeafNode)node).getClassValue();
    }
    else {
      // node has to be instance of interior node
      // in this case, we need to get the proper instance
      InteriorNode in = (InteriorNode)node;
      Instance inst1 = getInstance(inst);
      String value = inst1.stringValue(in.getAttribute());

      String siteToken = in.branchSite(value);
      // Update outgoing token and call appropriate site's locallyClassifyInst
      // Still to do...
      // compute SiteNum from token
      int startindex = siteToken.lastIndexOf("S") + 1;
      int endindex = siteToken.lastIndexOf("L");
      int siteNum =
	(Integer.valueOf(siteToken.substring(startindex,endindex))).intValue();

      if (siteNum == 1) {
	return m_Master.locallyClassifyInstance(inst, siteToken);
      }
      else {
	return m_Slaves[siteNum-2].locallyClassifyInstance(inst, siteToken);
      }
    }
  }

  public double[] localDistributionForInstance(Instance inst, String token) throws RemoteException { 
    TreeNode node = (TreeNode)m_classificationTbl.get(token);
    if (node instanceof LeafNode) {
      return ((LeafNode)node).getDistribution();
    }
    else {
      // node has to be instance of interior node
      // in this case, we need to get the proper instance
      InteriorNode in = (InteriorNode)node;
      Instance inst1 = getInstance(inst);
      String value = inst1.stringValue(in.getAttribute());

      String siteToken = in.branchSite(value);
      // Update outgoing token and call appropriate site's locallyClassifyInst
      // Still to do...
      // compute SiteNum from token
      int startindex = siteToken.lastIndexOf("S") + 1;
      int endindex = siteToken.lastIndexOf("L");
      int siteNum =
	(Integer.valueOf(siteToken.substring(startindex,endindex))).intValue();

      if (siteNum == 1) {
	return m_Master.localDistributionForInstance(inst, siteToken);
      }
      else {
	return m_Slaves[siteNum-2].localDistributionForInstance(inst, siteToken);
      }
    }
  }

  // Determines the max info gain (both value and attribute.
  // Should look at the stack to determine what attributes are still remaining
  // to be looked at though
  // the attribMaxInfoGain should also locally set information to be
  // appropriate (such as best attrib etc). 
  // !!!
  public double attribMaxInfoGain() throws RemoteException {
    // set m_classifyingAttribute somewhere
    // Subtracting two for key attrib and dummy class attrib
    int numAttr = m_insts.numAttributes() - m_attributeStack.size() - 2;
    if (numAttr <= 0)
      return 0;

    double[] infoGains = new double[m_insts.numAttributes()];
    // The call to fixHosts is necessary bfr entropy call to fix transaction
    // vectors at other sites
    int numOrigInsts = returnNumInsts();
    double origInfo;
    if (numOrigInsts > 0) {
      origInfo = computeCurrentEntropy(numOrigInsts);
    }
    else {
      origInfo = 0;
    }
    Enumeration attEnum = m_insts.enumerateAttributes();
    while (attEnum.hasMoreElements()) {
      Attribute att = (Attribute) attEnum.nextElement();
      if (att.equals(m_insts.classAttribute()) == false &&
	  att.name().equals("_keyAttr") == false &&
	  m_attributeStack.contains(att) == false) {
	infoGains[att.index()] = computeInfoGain(origInfo, numOrigInsts, att);
      }
      else {
	infoGains[att.index()] = -1;
      }
    }

    int index = Utils.maxIndex(infoGains);
    m_classifyingAttribute = m_insts.attribute(index);
    return infoGains[index];
  }

 /**
  * Computes the entropy of a dataset.
  * 
  * @return the entropy of the data's class distribution
  */
  private double computeCurrentEntropy(int numOrigInsts) throws RemoteException {

    double [] classCounts = new double[m_numClasses];

    // Compute class counts
    for (int i=0; i<m_numClasses; i++) {
      m_Master.prepareTransVectorWithClassFilter(i);
      classCounts[i] = SetIntersect();
    }
    
    double entropy = 0;
    for (int j = 0; j < m_numClasses; j++) {
      if (classCounts[j] > 0) {
        entropy -= classCounts[j] * Utils.log2(classCounts[j]);
      }
    }
    entropy /= (double) numOrigInsts;
    return entropy + Utils.log2(numOrigInsts);
  }

  /**
   * Computes information gain for an attribute.
   *
   * @param origInfo the information (entropy) of the original data
   * @param numOrigInsts the number of instances of original data
   * @param att the attribute
   * @return the information gain for the given attribute and data
   */
  private double computeInfoGain(double origInfo, int numOrigInsts, Attribute att) 
    throws RemoteException {
      // prepareTransVector has already been correctly called for other sites by
      // computeCurrentEntropy(). That function has to have been called earlier
      // otherwise this wont work (in that case we should simply run
      // prepareTransVector on all the sites)
      for (int j = 0; j < att.numValues(); j++) {
	m_requirementStack.push(new InfoObject(att, att.value(j)));
// at this point who reinitialized master?
	int numInsts = returnNumInsts();
	if (numInsts > 0) {
	  origInfo -= ((double) numInsts /
		     (double) numOrigInsts) * computeCurrentEntropy(numInsts);
	}
	m_requirementStack.pop();
      }

    return origInfo;
  }

  private void fixHosts() throws RemoteException{
    m_Master.prepareTransVector();
    for (int i = 1; i<m_nhosts; i++) {
      if (i+1 != m_siteNum)
	m_Slaves[i-1].prepareTransVector();
    }
  }

  private int returnNumInsts() throws RemoteException {
    // Compute number of instances
    fixHosts();
    prepareTransVector();
    int numOrigInsts = SetIntersect();
    return numOrigInsts;
  }

  /** @return The new token for the node */
  public String buildClassifier(String token) throws RemoteException {

    try {
      if (isNumAttributesZero(token) == true) {
	if (debug)
	  System.out.println("Num attr is ZERO");
	// create leaf node or some such thing
	TreeNode leaf = formMajorityClassLeaf(token);
	String outToken;
	if (token.equals("") == true) {
	  outToken = new String(token);
	} else {
	  outToken = m_Master.updateToken(m_siteNum, token);
	}

	System.out.println("Creating leaf at " + token + " ClassValue: " +
	    ((LeafNode)leaf).getClassValue());
	m_classificationTbl.put(outToken, leaf);

	// Leaf being created at this site
	return outToken;
      }
      else if (allTransHaveSameClass(token) == true /*all have same class*/) {
	if (debug)
	  System.out.println("all trans have same class");
	// create leaf node holding majority class
	TreeNode leaf = formLeafNode(token);
	String outToken;
	if (token.equals("") == true) {
	  outToken = new String(token);
	} else {
	  outToken = m_Master.updateToken(m_siteNum, token);
	}

	System.out.println("Creating leaf at " + token + " ClassValue: " +
	    ((LeafNode)leaf).getClassValue());
	m_classificationTbl.put(outToken, leaf);
	// Leaf being created at this site
	return outToken;
      }
      else {
	if (debug)
	  System.out.println("neither, buddy, neither");
	// find best attribute
        // Compute attribute with maximum information gain.
        double[] infoGains = new double[m_nhosts];
	infoGains[0] = m_Master.attribMaxInfoGain();
	for (int i=1; i<m_nhosts; i++) {
	  infoGains[i] = m_Slaves[i-1].attribMaxInfoGain();
	}

        int maxIndex = Utils.maxIndex(infoGains);
	System.out.println("maxindex is" + maxIndex);
            
        // Make leaf if information gain is zero. 
        // Otherwise create successors.
        if (Utils.eq(infoGains[maxIndex], 0)) {
	  TreeNode leaf = formMajorityClassLeaf(token);
	  String outToken;
	  if (token.equals("") == true) {
	    outToken = new String(token);
	  } else {
	    outToken = m_Master.updateToken(m_siteNum, token);
	  }

	  System.out.println("Creating leaf at " + token + " ClassValue: " +
	      ((LeafNode)leaf).getClassValue());
	  m_classificationTbl.put(outToken, leaf);
	  return outToken;
        } else {
	  if (maxIndex == 0) {
	    // I believe I dont really need to do this at all..
	    //updateStack();
	    // Fix the token either here or in lBC as in lClassifyInst
		// Hardcoding master site to 1
	    String outToken = m_Master.updateToken(SiteOther.MASTER_SITE,token);
	    m_Master.locallyBuildClassifier(outToken);
	    return outToken;
	  }
	  else {
	    // I believe I dont really need to do this at all..
	    //m_Slaves[maxIndex-1].updateStack();
	    // Fix the token either here or in lBC as in lClassifyInst
	    String outToken = m_Master.updateToken(maxIndex+1,token);
	    m_Slaves[maxIndex-1].locallyBuildClassifier(outToken);
	    return outToken;
	  }
	  
	  // maybe pop things off the stack - Not sure yet
        }
      }
    }
    catch (NoSuchAlgorithmException e) {
      System.out.println("BULLSHIT" + e);
    }

    return new String("Should never come here??");
  }


  // This is the method to call when the best classifying attribute has been
  // identified. It should basically just update the requirements and send a
  // call to buildClassifier
  public void locallyBuildClassifier(String token) throws RemoteException {

    m_attributeStack.push(m_classifyingAttribute);
    InteriorNode t = new InteriorNode(m_classifyingAttribute);
    System.out.println("Forming interior node at " + token + " Attribute: " +
	m_classifyingAttribute.name());

    for (int i=0; i<m_classifyingAttribute.numValues(); i++) {
      m_requirementStack.push(new InfoObject(m_classifyingAttribute,
	    m_classifyingAttribute.value(i)));
      m_currClassAttrInfoStack.push(new classInfo(m_classifyingAttribute,
	    m_Distribution));
      String outToken = buildClassifier(token);
      classInfo c = (classInfo)m_currClassAttrInfoStack.pop();
      m_classifyingAttribute = c.getAttribute();
      m_Distribution = c.getDistribution();
      System.out.println("Adding branch at " + m_classifyingAttribute.name() +
" = " + m_classifyingAttribute.value(i) + ", Token: " + outToken);
      t.addBranch(m_classifyingAttribute.value(i), outToken);
      m_requirementStack.pop();
    }

    m_classificationTbl.put(token, t);
    // Need to also pop things off stack just before return
    m_attributeStack.pop();
    return;
  }

  public void prepareSet() throws RemoteException {
    m_set = new HashSet(m_insts.numInstances());
    for (int i=0; i<Array.getLength(m_transVector); i++) {
      if (Array.getBoolean(m_transVector, i) == true) {
	m_set.add(m_phellman.Encrypt(new BigInteger(String.valueOf(i))));
      }
    }
  }

  public int SetIntersect() throws RemoteException {
    m_Master.prepareSet();
    for (int i = 1; i<m_nhosts; i++)
      m_Slaves[i-1].prepareSet();

    if (m_siteNum == m_nhosts) {
      m_Master.EncryptAndSendOn(m_set, m_nhosts - 1, m_siteNum);
    }
    else {
      m_Slaves[m_siteNum-1].EncryptAndSendOn(m_set, m_nhosts - 1, m_siteNum);
    }

    m_Master.TransferLocalSet(m_siteNum);
    for (int i = 1; i<m_nhosts; i++) {
      if (i+1 != m_siteNum) {
	m_Slaves[i-1].TransferLocalSet(m_siteNum);
      }
    }

    Set int_set = new HashSet(m_enc_sets[0]);
    for (int i=1; i<m_nhosts; i++) {
      int_set.retainAll(m_enc_sets[i]);
    }

    return int_set.size();
  }

  public void EncryptAndSendOn(Set in_set, int nhosts, int destSite) throws RemoteException {
    Set out_set = new HashSet(in_set.size());
    Iterator it = in_set.iterator();
    while (it.hasNext() == true) {
      out_set.add(m_phellman.Encrypt((BigInteger)it.next()));
    }

    if (nhosts <= 1) {
      // return to first site
      if (destSite == SiteOther.MASTER_SITE) {
	m_Master.returningSet(out_set, m_siteNum);
      }
      else {
	m_Slaves[destSite - 2].returningSet(out_set, m_siteNum);
      }
    }
    else {
      if (m_siteNum == m_nhosts) {
	m_Master.EncryptAndSendOn(out_set, nhosts - 1, destSite);
      }
      else {
	m_Slaves[m_siteNum - 1].EncryptAndSendOn(out_set, nhosts - 1, destSite);
      }
    }
  }

  public void TransferLocalSet(int siteNum) throws RemoteException {
    if (m_siteNum == m_nhosts) {
      m_Master.EncryptAndSendOn(m_set, m_nhosts - 1, siteNum);
    }
    else {
      m_Slaves[m_siteNum - 1].EncryptAndSendOn(m_set, m_nhosts - 1, siteNum);
    }
  }

  public void returningSet(Set fin_set, int sourceSiteNum) throws
    RemoteException {
    m_enc_sets[sourceSiteNum - 1] = fin_set;
  }

  static private void registerTestInstances() {
    g_instHashtbl = new Hashtable();
    Enumeration e = g_test_insts.enumerateInstances();
    Attribute att = g_test_insts.attribute("_keyAttr");
    while (e.hasMoreElements()) {
      Instance inst = (Instance)e.nextElement();
      g_instHashtbl.put(inst.stringValue(att),inst);
    }
  }

  static public void main(String [] args) throws Exception{
        
    if (args.length < 3) {
      System.err.println("Parameters: <Training File> <Test File> <SiteNum>");
      return;
    }

    String instancesFileName = args[0];
    BufferedReader instancesReader = new BufferedReader(new
	FileReader(instancesFileName));
    g_insts = new KeyedInstances(instancesReader);
    if (g_insts.classIndex() < 0) {
      g_insts.setClassIndex(g_insts.numAttributes() - 1);
    }
      
    String testFileName = args[1];
    BufferedReader testReader = new BufferedReader(new
	FileReader(testFileName));
    g_test_insts = new KeyedInstances(testReader);
    if (g_test_insts.classIndex() < 0) {
      g_test_insts.setClassIndex(g_test_insts.numAttributes() - 1);
    }

    registerTestInstances();

	String siteNum = args[2];
        SiteOther mySelf = new SiteOther(Integer.valueOf(siteNum).intValue());
                    
        System.setSecurityManager(new RMISecurityManager());
        try{        
            System.out.println("START");
            RmtSlave server = mySelf;
            System.out.println("ABOUT TO BIND");
            Naming.rebind("Site"+siteNum,server);
            System.out.println("Site" + siteNum + " is registered");
        } catch (java.io.IOException e){
            System.out.println("Error Registering Server"+e);
        }
    }

}

