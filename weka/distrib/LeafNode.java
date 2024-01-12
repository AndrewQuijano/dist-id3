package weka.distrib;

public class LeafNode extends TreeNode {
  /** Class value */
  private double m_ClassValue;

  /** Class distribution */
  private double[] m_Distribution;

  public LeafNode() {
  }

  public LeafNode(double classval, double[] distrib) {
    m_ClassValue = classval;
    m_Distribution = distrib;
  }

  public double getClassValue() {
    return m_ClassValue;
  }

  public double[] getDistribution() {
    return m_Distribution;
  }
}
