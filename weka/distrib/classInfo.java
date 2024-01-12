package weka.distrib;

import weka.core.Attribute;

public class classInfo {
  private Attribute m_attribute;
  private double[] m_distribution;

  public classInfo(Attribute attr, double[] distrib) {
    m_attribute = attr;
    m_distribution = distrib; // Am not sure if this assigns properly
  }

  public Attribute getAttribute() {
    return m_attribute;
  }

  public double[] getDistribution() {
    return m_distribution;
  }
}

