////////////////////////////////////////////////////////////////////
//
// 	CS555: Cryptography
// 	Project: Secure Multi-Party Scalar Product Protocol
// 	Students: Ronaldo Ferreira
// 		  Shan Lei
// 		  Paul Ruth
//
// 	DenseCipher.java: this file contains the implementation of the
// 	homomorphic encryption scheme. It contains the functions
//	used to perform encryption and decryption.
//
////////////////////////////////////////////////////////////////////
package weka.distrib;
import java.math.BigInteger;

class DenseCipher {
    DensePublicKey PubK;
    DensePrivateKey PriK;
    Dense cipher;
    int prec;
    BigInteger u;
    final int LongSize = 8;
    
    // this constructor is supposed to be used in a site that
    // will ONLY ENCRYPT messages
    DenseCipher(DensePublicKey pk)
    {
	BigInteger two = new BigInteger("2");

	PubK = pk;
	u = new BigInteger("3");
	while (u.gcd(PubK.n).intValue() != 1)
	    u = u.add(two);
	u = u.modPow(PubK.r, PubK.n);
    }
    
    // this constructor is supposed to be used in a site that
    // will ONLY DECRYPT messages
    DenseCipher(DensePrivateKey pk)
    {
	PriK = pk;
	prec = 0;
    }
    
    // this constructor is supposed to be used in a site that
    // ENCRYPT AND DECRYPT messages
    DenseCipher(DensePrivateKey pri, DensePublicKey pub)
    {
	BigInteger two = new BigInteger("2");

	PriK = pri;
	PubK = pub;
	prec = 0;
	
	u = new BigInteger("3");
	while (u.gcd(PubK.n).intValue() != 1)
	    u = u.add(two);
	u = u.modPow(PubK.r, PubK.n);
    }

        // this constructor is supposed to be used in a site that
    // ENCRYPT AND DECRYPT messages
    DenseCipher(Dense cip)
    {
	BigInteger two = new BigInteger("2");

	PriK = cip.GetPrivateKey();
	PubK = cip.GetPublicKey();
	cipher = cip;

	if (cip.prec_l != null)
	    prec = 1;
	else if (cip.prec_cip != null)
	    prec = 2;
	else
	    prec = 0;
	
	u = new BigInteger("3");
	while (u.gcd(PubK.n).intValue() != 1)
	    u = u.add(two);
	u = u.modPow(PubK.r, PubK.n);
    }

    // encryption function
    public BigInteger Encrypt(BigInteger message)
    {
	return ((PubK.y.modPow(message,PubK.n)).multiply(u)).mod(PubK.n);
    }

    // decryption function 
    public BigInteger Decrypt(BigInteger cip)
    {

	if (prec == 1) {
	    cip = cip.modPow(PriK.kz, PriK.n);
	    long lcip = cip.longValue();
	    for (int m = 0; m < cipher.max_value; m++)
		if (cipher.prec_l[m] == lcip)
		    return BigInteger.valueOf(m);
	    System.out.println("There is something wrong in the Decrypt function");
	    System.exit(0);
	    return BigInteger.valueOf(0);
	}
	if (prec == 2) {
	    cip = cip.modPow(PriK.kz, PriK.n);
	    long lcip = cip.longValue();
	    return cipher.FindByCip(lcip);
	}
	else {
	    BigInteger m;		// decrypted message
	    BigInteger x, aux;	// auxiliary variables
	    
	    m = new BigInteger("0");
	    
	    // executes a particular case when m=0
	    x = (PriK.y.modPow(m, PriK.n)).modInverse(PriK.n);
	    aux = x.multiply(cip);
	    aux = aux.modPow(PriK.kz, PriK.n);
	    
	    // continues execution until you find the correct message
	    while (aux.compareTo(BigInteger.ONE) != 0) {
		m = m.add(BigInteger.ONE);
		x = (PriK.y.modPow(m, PriK.n)).modInverse(PriK.n);
		aux = x.multiply(cip);
		aux = aux.modPow(PriK.kz, PriK.n);
	    }
	    
	    return m;
	}
    }

    BigInteger[][] EncryptLongVector(long[]vec, int block_mask, int txt_blk_size)
    {
	BigInteger[][] cip;
	long l_aux, aux;

	int vec_els = LongSize / (txt_blk_size / 8);
	cip = new BigInteger[vec.length][vec_els];
    	for (int i = 0; i < vec.length; i++) {
	    l_aux = vec[i];
	    for (int k = 0; k < vec_els; k++) {
		aux = l_aux & block_mask;
		l_aux >>= txt_blk_size;
		cip[i][k] = Encrypt(BigInteger.valueOf(aux));
	    }
	}
	return cip;
    }

    long[] DecryptLongVector(BigInteger[][]cip, int txt_blk_size)
    {
	long aux;
	long[]v = new long[cip.length];

	int vec_els = LongSize / (txt_blk_size / 8);
    	for (int i = 0; i < cip.length; i++) {
	    aux = 0;
	    for (int k = vec_els-1; k >= 0; k--) {
		aux <<= txt_blk_size;
		aux += (Decrypt(cip[i][k])).longValue();
	    }
	    v[i] = aux;
	}
	return v;
    }

}
