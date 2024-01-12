package weka.distrib;
import java.math.BigInteger;
import java.util.*;
import java.security.*;

class PohligHellman {
    Dense cipher;
    BigInteger m_p;
    BigInteger m_e;
    BigInteger m_d;
    int m_bitLength;
    int prec;
    BigInteger u;
    final int LongSize = 8;
    
    PohligHellman(BigInteger p, int bitLength) throws NoSuchAlgorithmException{
      m_p = p;
      Random rnd = SecureRandom.getInstance("SHA1PRNG");
      long seed = (Calendar.getInstance()).getTimeInMillis();
      rnd.setSeed(seed);
      m_bitLength = bitLength;
      m_e = BigInteger.probablePrime(m_bitLength/2, rnd);
    }

    // encryption function
    public BigInteger Encrypt(BigInteger message)
    {
      return message.modPow(m_e, m_p);
    }

    // decryption function 
    public BigInteger Decrypt(BigInteger cip)
    {
      // UnImplemented for now since it is not required
      return BigInteger.ZERO;
    }
}
