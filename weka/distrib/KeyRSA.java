package weka.distrib;

import java.math.BigInteger;
import java.security.SecureRandom;

public class KeyRSA implements java.io.Serializable{
    public BigInteger n;
    public BigInteger key;

    public KeyRSA(KeyRSA aKey){
	n = aKey.n;
	key = aKey.key;
    }

    public KeyRSA(BigInteger an, BigInteger akey){
	n = an;
	key = akey;
    }
}
