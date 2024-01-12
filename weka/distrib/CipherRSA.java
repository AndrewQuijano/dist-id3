package weka.distrib;

import java.math.BigInteger;
import java.security.SecureRandom;

public class CipherRSA
{
    private KeyRSA myKey;
    
    public CipherRSA()
    {}
    
    public CipherRSA(KeyRSA aKey){
	myKey = aKey;
    }

    public void init(KeyRSA aKey){
	myKey = aKey;
    }

    public BigInteger cipher(BigInteger message)
    {
        return message.modPow(myKey.key, myKey.n);
    }
    public byte[] cipher(byte[] message){
	int i;
	byte[] c=new byte[9];
	c[0]=0;
	for (i=0;i<8;i++)
	   c[i+1]=message[i];

	byte[] a=(new BigInteger(c)).modPow(myKey.key, myKey.n).toByteArray();

	if (a.length!=8){
	    byte[] b=new byte[8];
	    if (a.length>8){
		for (i=0;i<8;i++)
		    b[i]=a[i+1];
	    }
	    else{
		for (i=0;i<8-a.length;i++)
		    b[i]=0;
		for(;i<8;i++)
		    b[i]=a[i-(8-a.length)];
	    }
	    return b;
	}
	else
	    return a;
    }

}

