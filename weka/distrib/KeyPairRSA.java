package weka.distrib;

import java.math.BigInteger;
import java.security.SecureRandom;

public class KeyPairRSA implements java.io.Serializable {
    KeyRSA publicKey;
    KeyRSA privateKey;
    public KeyPairRSA(int bitlen){
     	SecureRandom r = new SecureRandom();
        BigInteger p = new BigInteger(bitlen / 2, 64, r);
        BigInteger q = new BigInteger(bitlen / 2, 64, r);
        BigInteger one = new BigInteger("1"); 
        BigInteger n = p.multiply(q);
	BigInteger m = p.subtract(one).multiply(q.subtract(one));
        BigInteger e = new BigInteger("3");
        while(m.gcd(e).intValue() > 1) e = e.add(new BigInteger("2"));
        BigInteger d = e.modInverse(m);

	publicKey = new KeyRSA(n, d);
	privateKey = new KeyRSA(n, e);
    }

    public KeyRSA getPublicKey(){
	return publicKey;
    }
    
    public KeyRSA getPrivateKey(){
	return privateKey;
    }
}
