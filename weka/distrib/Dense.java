////////////////////////////////////////////////////////////////////
//
// 	CS555: Cryptography
// 	Project: Secure Multi-Party Scalar Product Protocol
// 	Students: Ronaldo Ferreira
// 		  Shan Lei
// 		  Paul Ruth
//
// 	Dense.java: this file contains the implementation of the
// 	homomorphic encryption scheme, mainly the key generation
//	routine.
//
////////////////////////////////////////////////////////////////////
package weka.distrib;
import java.io.*;
import java.util.*;
import java.math.BigInteger;
import java.security.*;

class Dense
{
    private BigInteger n, y, r, kz;
    public CipTable prec_cip;
    public long[] prec_l;
    public int max_value;
    
    public DensePublicKey GetPublicKey() {
	return new DensePublicKey(y, n, r);
    }

    public DensePrivateKey GetPrivateKey() {
	return new DensePrivateKey(y, n, kz);
    }

    boolean CheckPrime(int r)
    {
	for (int i = 3; i < r/2; i += 2)
	    if ((r % i) == 0)
		return false;
	return true;
    }

    public BigInteger FindByCip(long cip)
    {
	return BigInteger.valueOf(prec_cip.Find(cip));
    }

    public Dense(int txt_blk_size, int cip_blk_size, int prec,
		 String KeyFileName, int show)
    {
	
	BigInteger p, q;
	int min_r = 1 << txt_blk_size;
	File fileObject;
	BufferedReader fileReader;

	try {
	    fileObject = new File(KeyFileName);	
	    fileReader = new BufferedReader(new FileReader(KeyFileName));

	    String s_aux = fileReader.readLine();
	}
	catch (Exception ex) {
	    System.err.println("IO error");
	    System.exit(1);
	}
	// prec == 3: does not pre-compute the cipher table
	// prec == 4: pre-compute the cipher table, but does not sort it
	// prec == 5: pre-compute and sort the cipher table
	if (prec == 4) {
	    prec_cip = null;
	    prec_l = new long[min_r];
	    
	    BigInteger aux;
	    
	    for (int i = 0; i < min_r; i++) {
		aux = kz.multiply(BigInteger.valueOf(i));
		aux = y.modPow(aux, n);
		prec_l[i] = aux.longValue();
	    }
	}
	else if (prec == 5) {
	    prec_cip = new CipTable(min_r);
	    prec_l = null;
	    BigInteger aux;
	    
	    for (int i = 0; i < min_r; i++) {
		aux = kz.multiply(BigInteger.valueOf(i));
		aux = y.modPow(aux, n);
		prec_cip.table[i] = new CipTableEntry(aux.longValue(), i);
	    }
	    prec_cip.Sort();
	}
    }
    
    public Dense(int txt_blk_size, int cip_blk_size, int prec, int show) throws
NoSuchAlgorithmException
    {
	SecureRandom r1;
	BigInteger p, q;
	BigInteger one = new BigInteger("1");
	BigInteger two = new BigInteger("2");
	BigInteger p2;
	int ctr;

	int min_r = 1 << txt_blk_size;
	int max_itr = 100000;
	r1 = SecureRandom.getInstance("SHA1PRNG");
	r1.setSeed((new Date()).getTime());
	    
	max_value = min_r;
	do {
	    do {
		p = BigInteger.probablePrime(cip_blk_size / 2, r1);
		q = BigInteger.probablePrime(cip_blk_size / 2, r1);
		
		n = p.multiply(q);

		if (show != 0) {
		    System.out.println("n = " + n);
		    System.out.println("p = " + p);
		    System.out.println("q = " + q);
		}
		p = p.subtract(BigInteger.ONE);
		q = q.subtract(BigInteger.ONE);
		
		r = one.add(BigInteger.valueOf(min_r));

		if (show != 0)
		    System.out.println("r = " + r);
		ctr = 0; 
		do {
		    if (ctr < max_itr) {
			if (p.mod(r).compareTo(BigInteger.ZERO) == 0) {
			    p2 = p.divide(r);
			    if (show != 0)
				System.out.println("r = " + r);
			    if (p2.gcd(r).intValue() == 1) {
				if (q.gcd(r).intValue() == 1 && CheckPrime(r.intValue()))
				    break;
				else
				    r = r.add(two);
			    }
			    else
				r = r.add(two);
			}
			else
			    r = r.add(two);
		    }
		    else
			break;
		    ctr++;
		} while (r.compareTo(p) < 0);
		
		if (ctr < max_itr && r.compareTo(p) < 0) {
		    if (show != 0)
			System.out.println("Found r = " + r);
		    break;
		}
		else {
		    if (show != 0)
			System.out.println("Could not find r, it will try different p and q");
		}
	    } while (true);
	
	    // JSV !!!!! - added by Me
	    min_r = r.intValue();
	    max_value = min_r;
    
	    p = (p.multiply(q)).divide(r);
	    kz = p;
	    y = new BigInteger("3");
	    do {
		while (y.modPow(p, n).compareTo(BigInteger.ONE) == 0)
		    y = y.add(two);
		if (y.gcd(n).intValue() == 1)
		    break;
	    } while (y.compareTo(n) < 0);
	    
	    if (y.compareTo(n) < 0) {
		if (show != 0)
		    System.out.println("Found y=" + y);
		break;
	    }
	    else {
		if (show != 0)
		    System.out.println("Could not find y, it will try different p and q");
	    }
	} while (true);

	// prec == 0: does not pre-compute the cipher table
	// prec == 1: pre-compute the cipher table, but does not sort it
	// prec == 2: pre-compute and sort the cipher table
	if (prec == 1) {
	    prec_cip = null;
	    prec_l = new long[min_r];
	    
	    BigInteger aux;
	    
	    for (int i = 0; i < min_r; i++) {
		aux = kz.multiply(BigInteger.valueOf(i));
		aux = y.modPow(aux, n);
		prec_l[i] = aux.longValue();
	    }
	}
	else if (prec == 2) {
	    prec_cip = new CipTable(min_r);
	    prec_l = null;
	    BigInteger aux;
	    
	    for (int i = 0; i < min_r; i++) {
		aux = kz.multiply(BigInteger.valueOf(i));
		aux = y.modPow(aux, n);
		prec_cip.table[i] = new CipTableEntry(aux.longValue(), i);
	    }
	    prec_cip.Sort();
	}
    }
}


