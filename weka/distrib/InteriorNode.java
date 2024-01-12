package weka.distrib;

import weka.core.Attribute;
import java.util.Hashtable;

public class InteriorNode extends TreeNode {
  /** The deciding attribute for this node */
  Attribute m_attrib;

  /** The hashtable which maps attribute values to sites */
  Hashtable branch;

  InteriorNode(Attribute attr) {
    m_attrib = attr;
    branch = new Hashtable((int)(attr.numValues() * 1.5));
  }

  public Attribute getAttribute() {
    return m_attrib;
  }

  public void addBranch(String value, String token) {
    branch.put(value, token);
  }

  public String branchSite(String value) {
    return (String)branch.get(value);
  }
}
