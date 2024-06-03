package edu.fiu.adwise.weka.distrib;

import weka.core.Attribute;

public class InfoObject {
    private final Attribute m_attribute;
    private final String m_value;

    public InfoObject(Attribute attr, String val) {
        m_attribute = attr;
        m_value = val;
    }

    public Attribute returnAttribute() {
        return m_attribute;
    }

    public String returnValue() {
        return m_value;
    }
}

