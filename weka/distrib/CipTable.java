////////////////////////////////////////////////////////////////////
//
// 	CS555: Cryptography
// 	Project: Secure Multi-Party Scalar Product Protocol
// 	Students: Ronaldo Ferreira
// 		  Shan Lei
// 		  Paul Ruth
//
// 	CipTable.java: implementation of the table used to store
//	pre-computed cipher codes. This class has methods for
// 	sorting and searching the table.
//
////////////////////////////////////////////////////////////////////
package weka.distrib;
class CipTable
{
    CipTableEntry[] table;

    CipTable(int size)
    {
	table = new CipTableEntry[size];
    }

    public void Sort()
    {
	int min_i;
	long min_cip;
	
	int n = table.length;
	
	for (int i = 0; i < n-1; i++) {
	    min_i = i;
	    min_cip = table[i].cip;
	    for (int j = i+1; j < n; j++)
		if (table[j].cip < min_cip) {
		    min_i = j;
		    min_cip = table[j].cip;
		}
	    if (min_i != i) {
		CipTableEntry aux;
		
		aux = table[i];
		table[i] = table[min_i];
		table[min_i] = aux;
	    }
	}
    }

    public long Find(long cip)
    {
	int l, r, i;

	l = 0; r = table.length-1;
	i = (l+r)/2;
	while (table[i].cip !=  cip) {
	    if (cip < table[i].cip) 
		r = i - 1;
	    else
		l = i + 1;
	    i = (l + r) / 2;
	}
	return table[i].txt;
    }
}
