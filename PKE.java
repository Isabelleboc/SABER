import java.math.BigInteger;
import java.util.Arrays;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import org.bouncycastle.crypto.digests.SHAKEDigest;

public class PKE 
{
	//constants
	public static int l=3;
	public static int n=256;
	public static int eq=13;
	public static int ep=10;
	public static int et=4;
	public static int u=8;
	public static BigInteger two = BigInteger.valueOf(2);
	public static BigInteger four = BigInteger.valueOf(4);
	public static BigInteger eight = BigInteger.valueOf(8);
	public static BigInteger htemp= two.pow(eq-ep-1);
	public static BigInteger[] h1=  fillh1();
	public static BigInteger[] h2=  fillh2();
	public static BigInteger[][] h= fillh();

	public static byte[] KeyGen() throws Exception
	{
		byte[] seedA= randomBytes(32);
		seedA= shake128(256, seedA);
		
		BigInteger[][][] A = GenMatrix(seedA);
		
		byte[] seedS= randomBytes(32);
		BigInteger[][] s= GenSecret(seedS);
		

		BigInteger[][] b = polyvecMOD(polyvecADD(MatrixVectorMul(transpose(A), s ,two.pow(eq)),h), two.pow(eq)) ;
		
		for(int i=0; i<l; i++)
		{
			b[i] = SHIFTRIGHT(b[i], eq-ep);
		}
		
		byte[] SecretKeycpa = POLVEC2BS(s, eq);
		
		byte[] pk = POLVEC2BS (b , ep);

		ByteArrayOutputStream publicKey = new ByteArrayOutputStream();
		publicKey.write(seedA);
		publicKey.write(pk);
		byte[] PublicKeycpa = publicKey.toByteArray();
		
		ByteArrayOutputStream output = new ByteArrayOutputStream();
		output.write(PublicKeycpa);
		output.write(SecretKeycpa);
		byte[] Output = output.toByteArray();
		
		return Output;	
		
		/*
		 * returns ( pk:=( seedA , b ) , s )
		 * 		seedA: 32 bytes
		 * 		b: 960 bytes
		 * 		s: 1248 bytes
		 */
	}
	
	public static byte[] Enc(BigInteger[] m, byte[] seedS, byte[] PublicKeycpa) throws Exception
	{
		
		byte[] seedA = Arrays.copyOfRange(PublicKeycpa, 0, 32);
		
		byte[] pk = Arrays.copyOfRange(PublicKeycpa, 32, 992);
		
		
		BigInteger[][][] A = GenMatrix(seedA);
		//Formatter x = new Formatter ("PKEOutput.txt");
		//Driver.print(x, A, "A");
		BigInteger[][] sd = GenSecret(seedS);
		
		BigInteger[][] bd = polyvecMOD(polyvecADD(MatrixVectorMul(A,sd,two.pow(eq)),h),two.pow(eq));
		
		
		
		for(int i =0 ; i<l ; i++)
		{
			bd[i] = SHIFTRIGHT(bd[i], eq-ep);
		}
		
		BigInteger[][] b = BS2POLVEC(pk,ep);
		BigInteger[] vd = InnerProd(b, polyvecMOD(sd,two.pow(ep)),two.pow(ep));
		
		BigInteger[] mp = SHIFTLEFT(m, ep-1);
		
		BigInteger[] cm = SHIFTRIGHT(polyMOD(polyADD(polySUBTRACT(vd, mp),h1),two.pow(ep)), ep-et);
		
		
		
		
		
		byte[] cmBytes = POL2BS(cm,et);
		byte[] bdBytes = POLVEC2BS(bd,ep);
		ByteArrayOutputStream ciphertext= new ByteArrayOutputStream();
		ciphertext.write(cmBytes);
		ciphertext.write(bdBytes);
		
		
		
		byte[] CipherTextcpa = ciphertext.toByteArray();
		
		return CipherTextcpa;
		/*
		 * returns c:= (cm , b')
		 * 		cm: 128 bytes
		 * 		b': 960 bytes
		 */
	}
	
	public static byte[] Dec(byte[] CipherTextcpa, byte[] SecretKeycpa) throws IOException
	{
		
		BigInteger[][] s = BS2POLVEC(SecretKeycpa, eq);
		
		byte[] cm = Arrays.copyOfRange(CipherTextcpa, 0, 128);
		
		byte[] ct = Arrays.copyOfRange(CipherTextcpa, 128, 1088);
		
		
		BigInteger[] Cm = SHIFTLEFT(BS2POL(cm,et) , ep-et);
		
		
		BigInteger[][] bd= BS2POLVEC(ct, ep);
		
		BigInteger[] v = InnerProd(bd, polyvecMOD(s, two.pow(ep)),two.pow(ep));
		
		BigInteger[] md = SHIFTRIGHT(polyMOD(polyADD(polySUBTRACT(v,Cm),h2),two.pow(ep)),ep-1);
		
		byte[] m = POL2BS(md,1);

		
		return m;
		/*
		 * returns recovered message m 
		 */
	}
	
	public static byte[] randomBytes( int len)
	{
		// return byte string of random bytes of length len bytes 
		byte[] b= new byte[len];
		SecureRandom random = new SecureRandom();
		random.nextBytes(b);
		
		return b;
	}

	public static byte[] shake128 (int len, byte[] bs) throws Exception
	{
		
		//returns hashed seed with output length len
		SHAKEDigest digest = new SHAKEDigest(128);
		digest.update(bs, 0, bs.length);
		
		byte[] rv = new byte[len/8];
		digest.doFinal(rv, 0, len/8);
		return rv;
	}

	public static BigInteger[][][] GenMatrix(byte[] seedA) throws Exception
	{
		//generate Matrix A from given seed
		byte[] buf= shake128(l*l*n*eq,seedA);
		String Buf = convertBytesToBinaryString(buf);
		while(Buf.length()<(l*l*n*13))
		{
			Buf = "0" +Buf;
		}
		
		String[] split = new String[l*l*n];
		String temp =new String("");
		int index = l*l*n;
		for(int i= 0 ; i < Buf.length();i++)
		{
			
			temp+= Buf.charAt(i);
			if(i%(eq)==0)
			{
				index--;
				split[index]=temp;
				temp="";
			}
		}
		
		BigInteger[][][] A = new BigInteger[l][l][n];
		int k=0 ;
		for(int i1 =0; i1<l; i1++)
		{
			for(int i2=0; i2<l ; i2++)
			{
				for(int j =0; j<n ; j++)
				{
					A[i1][i2][j] = new BigInteger(split[k],2);
					k++;
				}
			}
		}
		return A;

	}
		

	public static BigInteger[][] GenSecret(byte[] seedS) throws Exception
	{
		//Generate Secret Vector with given seed
		byte[] buf = shake128(l*n*u, seedS);
		String Buf = convertBytesToBinaryString(buf);
		while(Buf.length()<(2*l*n*u/2))
		{
			Buf = "0" +Buf;
		}
		String[] split = new String[2*l*n];
		String temp =new String("");
		int index = 2*l*n;
		for(int i= 0 ; i < Buf.length();i++)
		{
			
			temp+= Buf.charAt(i);
			if(i%(u/2)==0)
			{
				index--;
				split[index]=temp;
				temp="";
			}
		}
		
		BigInteger[][] s = new BigInteger[l][n];
		int k=0; 
		for(int i=0; i <l ;i ++)
		{
			for(int j=0; j<n; j++)
			{
				s[i][j] = BigInteger.valueOf(HammingWeight(split[k])- HammingWeight(split[k+1]));
				s[i][j] = s[i][j].mod(two.pow(eq));
				k=k+2;
			}
		}
		return s;
	}
	
	
	public static BigInteger[][] MatrixVectorMul(BigInteger[][][] M, BigInteger[][] v, BigInteger q)
	{
		//performs multiplication on a matrix, given two polynomial vectors in Rq. Returns product the vector mv = M*v
		BigInteger[][] b = new BigInteger[l][n];	
		
		// ( A * s + h)
		for(int i=0;i<l;i++)
		{
			Arrays.fill(b[i], BigInteger.valueOf(0));
			for(int j=0; j<l;j++)
			{
				//b[i]+= A[i][j]+s[j]
				
				b[i]=polyADD(b[i],(PolyMult.PolyMul(M[i][j], v[j],q)));
			}
			b[i] =polyMOD(b[i], q);
		}
		
		return b;
	}

	public static BigInteger[] InnerProd(BigInteger[][] Va, BigInteger[][] Vb, BigInteger q)
	{
		//Computes inner product of two vectors and returns a polynomial in Rq
		BigInteger[] C= new BigInteger[n];
		Arrays.fill(C,  BigInteger.valueOf(0));
	
		for(int i=0; i<l; i++)
		{
			
			C =polyADD(C,PolyMult.PolyMul(Va[i], Vb[i],q));
		}
		return polyMOD(C, q);
	}

	public static BigInteger[][][] transpose(BigInteger[][][] A)
	{
		BigInteger[][][] B = new BigInteger[l][l][n];
	    for ( int i = 0; i < l; i++) 
	    {
	        for (int j = 0; j < l; j++) 
	        {
	            B[i][j] = A[j][i];
	        }
	    }
		return B;
	}

	public static int HammingWeight(String s)
	{
		// returns the Hamming Weight of given binary String, i.e. count how many 1's are in the binary string 
		int count=0;
		for(int i=0; i<s.length();i++)
		{
			if(s.charAt(i)=='1')
			{
				count++;
			}
		}
		return count;
	}

	public static byte[] POLVEC2BS(BigInteger[][] POLVEC, int k) 
	{
		//converts a polynomial vector into byte string 
		byte[] BS= new byte[l*k*n/8];
		String output = new String("");
		String temp = "";
		for(int i=0 ; i<POLVEC.length;i++)
		{
			for(int j=0 ; j<POLVEC[0].length;j++)
			{
				temp="";
				temp= POLVEC[i][j].toString(2);
				while(temp.length()< k)
				{
					temp = "0" + temp;
				}
				output+= temp;
			}
		}
		BS = new BigInteger(output,2).toByteArray();
		if(BS.length == l*k*n/8)
		{
			return BS;
		}
		byte[] Output = Arrays.copyOfRange(BS, 1, BS.length);
		return Output; 
	}
	
	
	public static byte[] POL2BS (BigInteger[] POL, int k) 
	{
		//converts polynomial into byte string
		byte[] BS= new byte[k*n/8];
		String output = new String("");
		String temp = "";
		for(int i=0 ; i<POL.length;i++)
		{
				temp="";
				temp= POL[i].toString(2);
				while(temp.length()< k)
				{
					temp = "0" + temp;
				}
				output+= temp;
		}
		//System.out.println("POL2BS output length:  " + output.length() + " bits");
		BS = new BigInteger(output,2).toByteArray();
		if(BS.length == k*n/8)
		{
			return BS;
		}
		byte[] Output = Arrays.copyOfRange(BS, 1, BS.length);
		return Output; 
	}
	
	
	public static BigInteger[][] BS2POLVEC(byte[] BS, int k)
	{
		//converts byte string into polynomial vector
		BigInteger[][] v= new BigInteger[l][n];
		String s = convertBytesToBinaryString(BS);
		while(s.length()< n*l*k)
		{
			s = "0" +s;
		}
		String temp=  new String("");
		int index=0;
		for(int i=0 ; i < l ; i++)
		{
			for(int j = 0 ; j <n; j++)
			{
				temp ="";
				for(int count = 0 ; count<k ; count++)
				{
					temp += s.charAt(index);
					index++;
				}
				v[i][j] = new BigInteger(temp,2);
			}
		}
		return v;
	}
	
	
	public static BigInteger[] BS2POL(byte[] BS, int k)
	{
		//converts byte string into polynomial
		BigInteger[] v= new BigInteger[n];
		String s = convertBytesToBinaryString(BS);
		
		//ensure string is the correct length
		while(s.length()< n*k)
		{
			s = "0" +s;
		}
		String temp=  new String("");
		int index=0;
		for(int i=0 ; i < n ; i++)
		{
			
				temp ="";
				for(int count = 0 ; count<k ; count++)
				{
					temp += s.charAt(index);
					index++;
				}
				v[i] = new BigInteger(temp,2);
			
		}
		return v;
	}
	
	public static String convertBytesToBinaryString(byte[] bytes)
	{
		//returns binary string representation of the given byte string 
		BigInteger bigInteger= new BigInteger(bytes);
		if(bigInteger.compareTo(BigInteger.ZERO)<0)
		{
			bigInteger = new BigInteger(1,bytes);
		}
		return bigInteger.toString(2);
	}

	public static BigInteger[] SHIFTLEFT(BigInteger[] POLin, int s)
	{
		//shift all coefficients in a polynomial left by 3 positions 
		BigInteger[] POLout = new BigInteger[POLin.length];
		for(int i=0 ;i<n;i++)
		{
			POLout[i]=POLin[i].shiftLeft(s);
		}
		return POLout;
	}
	
	public static BigInteger[] SHIFTRIGHT(BigInteger[] POLin, int s)
	{
		//shift all coefficients in a polynomial right by 3 positions 
		BigInteger[] POLout = new BigInteger[POLin.length];
		for(int i=0 ;i<n;i++)
		{
			POLout[i]=POLin[i].shiftRight(s);
		}
		return POLout;
	}
	
	public static BigInteger[] polyADD(BigInteger[] POL1, BigInteger[] POL2)
	{
		// add coefficients of two polynomials
		BigInteger[] C = new BigInteger[n];
		for(int i=0;  i<n; i++)
		{
			C[i] = POL1[i].add(POL2[i]);
		}
		return C;
	}

	
	public static BigInteger[][] polyvecADD(BigInteger[][] POLVEC1, BigInteger[][] POLVEC2)
	{
		// add coefficients of two polynomial vectors
		BigInteger[][] C =new BigInteger[l][n];
		for(int i=0; i<l; i++)
		{
			C[i] = polyADD(POLVEC1[i], POLVEC2[i]);
		}
		return C;
	}
	
	
	public static BigInteger[] polySUBTRACT(BigInteger[] POL1, BigInteger[] POL2)
	{
		//subtract coefficients of two polynomials
		BigInteger[] C = new BigInteger[n];
		for(int i=0;  i<n; i++)
		{
			C[i] = POL1[i].subtract(POL2[i]);
		}
		return C;
	}
	
	public static BigInteger[][] polyvecSUBTRACT(BigInteger[][] POLVEC1, BigInteger[][] POLVEC2)
	{
		//subtract coefficients of two polynomial vectors 
		BigInteger[][] C =new BigInteger[l][n];
		
		for(int i=0; i<l; i++)
		{
			C[i] = polySUBTRACT(POLVEC1[i], POLVEC2[i]);
		}
		return C;
	}
	
	public static BigInteger[] polyMOD(BigInteger[] POL, BigInteger q)
	{
		//mod each coefficient of the polynomial with q
		for(int i=0; i<n;i++)
		{
			POL[i]=POL[i].mod(q);
		}
		return POL;
	}
	
	
	public static BigInteger[][] polyvecMOD(BigInteger[][] POLVEC1, BigInteger q)
	{
		//mod each coefficient of the vecor polynomial with q
		BigInteger[][] C =new BigInteger[l][n];
		
		for(int i=0; i<l; i++)
		{
			C[i] = polyMOD(POLVEC1[i],q);
		}
		return C;
	}
	
	//fill constant arrays 
	public static BigInteger[] fillh1() 
	{
		BigInteger[] h1= new BigInteger[n];
		Arrays.fill(h1, htemp);
		return h1;
	}
	
	public static BigInteger[] fillh2()
	{
		BigInteger[] h2 =new BigInteger[n];
		Arrays.fill(h2, BigInteger.valueOf((int)(Math.pow(2, ep-2)-Math.pow(2, ep-et-1)+Math.pow(2, eq-ep-1))));
		return h2;
	}
	
	public static BigInteger[][] fillh()
	{
		BigInteger[][] h = new BigInteger[l][n];
		for(int i=0 ;i<h.length;i++)
		{
			Arrays.fill(h[i], htemp);	
		}
		return h;
	}
}
