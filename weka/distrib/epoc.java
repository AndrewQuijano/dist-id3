package weka.distrib;
import java.io.*;
import java.util.*;
import java.math.BigInteger;
import java.security.*;

class epoc
{
  private BigInteger m_n, m_g, m_h;
  private BigInteger m_p, m_gp;
  int m_pLen, m_mLen, m_hLen, m_rLen;

  public epoc(int k) throws NoSuchAlgorithmException {
    m_pLen = k;
    Random rnd = SecureRandom.getInstance("SHA1PRNG");
    rnd.setSeed((new Date()).getTime());
    long basicPrimeSize = Math.round(Math.log(k) / Math.log(2));
    long pqsize = k - basicPrimeSize;
  }
}


