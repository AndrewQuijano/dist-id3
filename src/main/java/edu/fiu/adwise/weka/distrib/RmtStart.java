package edu.fiu.adwise.weka.distrib;

import java.rmi.*;

import weka.core.Instance;

interface RmtStart extends Remote {
    void buildClassifier() throws Exception;

    double classifyInstance(Instance instance) throws Exception;

    double[] distributionForInstance(Instance instance) throws Exception;
}
