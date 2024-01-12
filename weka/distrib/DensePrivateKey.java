////////////////////////////////////////////////////////////////////
//
// 	CS555: Cryptography
// 	Project: Secure Multi-Party Scalar Product Protocol
// 	Students: Ronaldo Ferreira
// 		  Shan Lei
// 		  Paul Ruth
//
// 	DensePrivateKey.java: definition of the class used
// 	for storing private keys.
//
////////////////////////////////////////////////////////////////////
package weka.distrib;
import java.math.BigInteger;

class DensePrivateKey implements java.io.Serializable { 
    public BigInteger y, n, kz;
    
    DensePrivateKey(BigInteger ly, BigInteger ln, BigInteger lkz) {
	y = ly;
	n = ln;
	kz = lkz;
    }
}
