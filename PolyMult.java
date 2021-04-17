import java.util.Arrays;
import java.lang.Math;
import java.math.BigInteger;

public class PolyMult
{
	public static BigInteger two = BigInteger.valueOf(2);
	public static BigInteger four = BigInteger.valueOf(4);
	public static BigInteger eight= BigInteger.valueOf(8);	

	public static BigInteger[] PolyMul(BigInteger[] p, BigInteger[] q, BigInteger mod)
	{	
		//driver method
		BigInteger[][] splitP = split(pad(p));
		BigInteger[][] splitQ = split(pad(q));
		BigInteger[][] w = Evaluation(splitP,splitQ, mod);
		BigInteger[] C = interpolation(w, mod);	
		BigInteger[] C256 = reduce(C,mod);
		return C256;
	}
	
	public static BigInteger[] reduce(BigInteger [] poly, BigInteger mod)
	{
		int n=256;
		BigInteger[] polyRp =new BigInteger[n];  
		Arrays.fill(polyRp, BigInteger.valueOf(0));
		for(int i=0; i<poly.length;i++)
		{
			if(i>=n)
			{
				BigInteger temp = BigInteger.valueOf(-1).multiply(poly[i]);
				polyRp[(i-n)]= polyRp[(i-n)].add(temp);
			}
			else
			{
				polyRp[i%n]= polyRp[i%n].add(poly[i]);
			}
			//polyRp[i %(n)] = polyRp[i%(n)].add(poly[i]);
			polyRp[i%n]=polyRp[i%n].mod(mod);
		}
		return polyRp;
	}
	
	public BigInteger[] polyAddition(BigInteger[] poly1, BigInteger[] poly2)
	{
		int polyLength=0;

		if(poly1.length>poly2.length)
		{          
			polyLength=(poly1.length);
		}
	    else
	    {
			polyLength=(poly2.length);
	    }


		BigInteger[] sumPoly=new BigInteger[polyLength];
		for(int i=0;i<polyLength;i++)
		{
			sumPoly[i]=poly1[i].add(poly2[i]);
		}
		return sumPoly;
	}

	public BigInteger[] polyConstMult(BigInteger[] poly, BigInteger multiplier)
	{
		BigInteger[] constMultPoly=new BigInteger[poly.length];
		for(int i=0;i<poly.length;i++)
		{
			constMultPoly[i]=multiplier.multiply(poly[i]);
		}
		return constMultPoly;
	}
	
	private static BigInteger inverseModP(BigInteger a, BigInteger p)
	{
		return BigInteger.valueOf((a.modInverse(p)).intValue());
	}


	public static BigInteger polyConstDivision(BigInteger poly, BigInteger divisor, BigInteger mod)
	{

		BigInteger constDivPoly=new BigInteger("0");
		BigInteger NumberOfShifts =BigInteger.valueOf(4);            // Will be 1,2 or 3 depending on the Toom Cook division required
		BigInteger inverse= BigInteger.valueOf(0);                   // Will be the inverseModp

		// Sort out the sequence of multiplications and divisions

		if(divisor.compareTo(BigInteger.valueOf(2))==0)
		{
			NumberOfShifts=BigInteger.valueOf(1);
			inverse=BigInteger.valueOf(1);
		}
		else if(divisor.compareTo(BigInteger.valueOf(18))==0)
		{
			NumberOfShifts=BigInteger.valueOf(1);
			inverse=inverseModP(BigInteger.valueOf(9),mod);

		}
		else if(divisor.compareTo(BigInteger.valueOf(24))==0)
		{
			NumberOfShifts=BigInteger.valueOf(3);
			inverse=inverseModP(BigInteger.valueOf(3),mod);
		}
		else if(divisor.compareTo(BigInteger.valueOf(60))==0)
				{
					NumberOfShifts=BigInteger.valueOf(2);
					inverse=inverseModP(BigInteger.valueOf(15),mod);
		}
		else{
			System.out.println("Problem with constant division, illegal divisor encountered");
			System.exit(0);
		}

		constDivPoly=poly.multiply(inverse);
		constDivPoly=constDivPoly.shiftRight((NumberOfShifts).intValue());
		return constDivPoly;
	}

	
	public static BigInteger[] modP(BigInteger[] C, BigInteger mod)
	{
		
		BigInteger[] Res = new BigInteger[C.length];
		for(int i=0 ; i<C.length;i++)
		{
			Res[i]=C[i].mod(mod);
		}
		return Res;
	}
	
	
	public static BigInteger[][] Evaluation(BigInteger[][] A, BigInteger[][] B, BigInteger mod)
	{
		BigInteger[][] w= new BigInteger[8][64];
		BigInteger[][] wA= EvalHelper(A);
		BigInteger[][] wB= EvalHelper(B);
		for(int i=1; i<8;i++)
		{
			w[i]=SchoolBookMultiply(wA[i],wB[i]);
		}
		return w;
	}
	
	public static BigInteger[][] EvalHelper(BigInteger[][] A)
	{
		/*
		 * Eval A(x) at x = inf, 2 ,1 ,-1, 1/2, -1/2
		 * wx[1] = A(inf} = A[3]
		 * wx[2] = A(2) = A[0] + 2*A[1] + 4*A[2] + 8*A[3]
		 * wx[3] = A(1) = A[0] + A[1] + A[2] + A[3] 
		 * wx[4] = A(-1) = A[0] + A[1] + A[2] + A[3] 
		 * wx[5] = A(1/2) = 8*A[0] + 4*A[1] + 2*A[2] + A[3]
		 * wx[6] =  A(-1/2) = 8*A[0] - 4*A[1] + 2*A[2] - A[3]
		 * wx[7] = A(0) = A[0]
		 */
		BigInteger[][] wx = new BigInteger[8][64];
		BigInteger[] r = new BigInteger[8];
		
		
		for(int i=0;i<8;i++)
		{
			Arrays.fill(wx[i], BigInteger.valueOf(0));
		}
		for(int i=0;i<64;i++)
		{
			
			r[0]=A[0][i];
			r[1]=A[1][i];
			r[2]=A[2][i];
			r[3]=A[3][i];
			r[4]=r[0].add(r[2]);
			r[5]=r[1].add(r[3]);
			r[6]=r[4].add(r[5]);	
			r[7]=r[4].subtract(r[5]);
			wx[3][i]=r[6];
			wx[4][i] = r[7];
			r[4]= two.multiply(r[0].multiply(four).add(r[2]));
			r[5]=(r[1].multiply(four)).add(r[3]);
			r[6]= r[4].add(r[5]);
			r[7]=r[4].subtract(r[5]);
			wx[5][i]=r[6];
			wx[6][i]=r[7];
			r[4]=eight.multiply(r[3]).add(four.multiply(r[2])).add(two.multiply(r[1])).add(r[0]);
			wx[2][i]=r[4];
			wx[7][i]=r[0];
			wx[1][i]=r[3];
		}
		return wx;
	}
	
	public static BigInteger[] pad(BigInteger[] A)
	{
		//pad vector with 0 and return vector of length 256
		int len = A.length;
		BigInteger[] padded = new BigInteger[256];
		
		
		for(int i=0;i<256;i++)
		{
			if(i<len)
			{
				padded[i]=A[i];
			}
			else
			{
				padded[i]=BigInteger.valueOf(0);
			}
		}
		return padded;
		
	}
	public static BigInteger[][] split(BigInteger[] Ax)
	{
		//split polynomial A (of size 256 coefficients) into 4 polynomials (of size 64 polynomials)
		BigInteger[][] A = new BigInteger[4][64];
		int index=0;
		for(int i=0; i<4;i++)
		{
			for(int j=0; j<64; j++)
			{
				A[i][j] = Ax[index];
				
				index++;
			}
		}
		return A;
	}
	
	public static BigInteger[] interpolation(BigInteger[][] w, BigInteger mod)
	{
		// Toom Cook 4 way interpolation algorithm
		// returns polynomial C of size 512
		BigInteger[] C = new BigInteger[512];
		Arrays.fill(C, BigInteger.valueOf(0));
		
		BigInteger[] r= new BigInteger[9];
		
		for(int i=0; i<127;i++)
		{
			//r1=w2[i]
			r[1]=w[2][i];
			//r4=w5[i]
			r[4]=w[5][i];
			//r5=w6[i]
			r[5]=w[6][i];
			//r0=w1[i]
			r[0]=w[1][i];
			//r2=w3[i]
			r[2]=w[3][i];
			//r3=w4[i]
			r[3]=w[4][i];
			//r6=w7[i]
			r[6]=w[7][i];
			//r1=r1+r4
			r[1]=r[1].add(r[4]);
			//r5=r5-r4
			r[5]=r[5].subtract(r[4]);
			//r3=(r3-r2)/2
			r[3]= polyConstDivision((r[3].subtract(r[2])),two,mod);
			//r4=r4-r0
			r[4]=r[4].subtract(r[0]);
			//r8=64*r6
			r[8]= BigInteger.valueOf(64).multiply(r[6]);
			//r4=r4-r8
			r[4]=r[4].subtract(r[8]);
			//r4=2*r4+r5
			r[4]= (two.multiply(r[4])).add(r[5]);
			//r2=r2+r3
			r[2]=r[2].add(r[3]);
			//r1=r1-65*r2
			r[1]=r[1].subtract((BigInteger.valueOf(65).multiply(r[2])));
			//r2=r-r6
			r[2]=r[2].subtract(r[6]);
			//r2=r2-r0
			r[2]=r[2].subtract(r[0]);
			//r1=r1+45*r2
			r[1]=r[1].add(BigInteger.valueOf(45).multiply(r[2]));
			//r4=(r4-8*r2)/24
			r[4]= polyConstDivision((r[4].subtract((eight.multiply(r[2])))),(BigInteger.valueOf(24)),mod);
			//r5=r5+r1
			r[5]=r[5].add(r[1]);
			//r1=(r1+16*r3)/18
			r[1]=polyConstDivision((r[1].add(BigInteger.valueOf(16).multiply(r[3]))),(BigInteger.valueOf(18)),mod);
			//r3=-(r3+r1)
			r[3]= BigInteger.valueOf(-1).multiply(r[3].add(r[1]));
			//r5=(30*r1-r5)/60
			r[5]=polyConstDivision(((BigInteger.valueOf(30).multiply(r[1])).subtract(r[5])),(BigInteger.valueOf(60)),mod);
			//r2=r2-r4
			r[2]=r[2].subtract(r[4]);
			//r1=r1-r5
			r[1]=r[1].subtract(r[5]);
			
			
			
			C[i]=(C[i].add(r[6]));
			
			C[64+i] = (C[64+i].add(r[5]));
			
			C[128+i] = (C[128+i].add(r[4]));
			
			C[192+i] = (C[192+i].add(r[3]));
			
			C[256+i] = (C[256+i].add(r[2]));
			
			C[320+i] = (C[320+i].add(r[1]));
			
			C[384+i] = (C[384+i].add(r[0]));
		}
		
		return C; 
	}
	
	public static BigInteger[] SchoolBookMultiply(BigInteger[] A, BigInteger[] B)  
	{
		BigInteger[] C = new BigInteger[A.length +B.length]; 
		
		for (int i = 0; i < A.length + B.length ; i++)  
		{ 
			C[i] = BigInteger.valueOf(0); 
		} 
		
		for (int i = 0; i < A.length; i++)  
		{ 
			for (int j = 0; j < A.length; j++)  
			{ 
				//multiply using Karatsuba
				C[i+j] = (C[i+j].add(karatsuba(A[i],B[j])));
			} 
		} 
		return C; 
	} 
	
	 public static BigInteger karatsuba(BigInteger x, BigInteger y)
	 {
	     // cutoff to brute force
		 int N = Math.max(x.bitLength(), y.bitLength());
		 if (N <= 2000) 
	        	return x.multiply(y);                

		 // number of bits divided by 2
		 N = (N / 2) + (N % 2);

		 // x = a + 2^N b,   y = c + 2^N d
		 BigInteger b = x.shiftRight(N);
		 BigInteger a = x.subtract(b.shiftLeft(N));
		 BigInteger d = y.shiftRight(N);
		 BigInteger c = y.subtract(d.shiftLeft(N));

		 // compute sub-expressions with recursion
		 BigInteger ac    = karatsuba(a, c);
		 BigInteger bd    = karatsuba(b, d);
		 BigInteger abcd  = karatsuba(a.add(b), c.add(d));

		 return ac.add(abcd.subtract(ac).subtract(bd).shiftLeft(N)).add(bd.shiftLeft(2*N));
	 }
}
