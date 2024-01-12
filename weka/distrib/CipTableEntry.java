////////////////////////////////////////////////////////////////////
//
// 	CS555: Cryptography
// 	Project: Secure Multi-Party Scalar Product Protocol
// 	Students: Ronaldo Ferreira
// 		  Shan Lei
// 		  Paul Ruth
//
// 	CipTableEntry.java: definition of an entry in the cipher
//	table used to store pre-computed values in the homomorphic
// 	encryption scheme.
//
////////////////////////////////////////////////////////////////////
package weka.distrib;
class CipTableEntry
{
    public long cip;
    public long txt;

    CipTableEntry(long c, long t)
    {
	cip = c;
	txt = t;
    }
}
