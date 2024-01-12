////////////////////////////////////////////////////////////////////
//
// 	CS555: Cryptography
// 	Project: Secure Multi-Party Scalar Product Protocol
// 	Students: Ronaldo Ferreira
// 		  Shan Lei
// 		  Paul Ruth
//
// 	DensePublicKey.java: definition of the class used
// 	for storing public keys.
//
////////////////////////////////////////////////////////////////////
package weka.distrib;
import java.math.BigInteger;

class DensePublicKey implements java.io.Serializable {
    public BigInteger y, n, r;
    
    DensePublicKey(BigInteger ly, BigInteger ln, BigInteger lr) { 
	y = ly;
	n = ln;
	r = lr;
    }
}
