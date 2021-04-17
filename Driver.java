
import java.math.BigInteger;
import java.util.*;
import java.io.File;
import java.io.IOException;
/**
 * @author isabelle
 * 
 *  
 *
 */
public class Driver
{
	public static int l=3;
	public static int n=256;
	public static int eq=13;
	public static int ep=10;
	public static int et=4;
	public static int u=8;
	
	public static void main(String args[]) throws Exception
	{
		//call methods 
		pke();
		kem();
	}
	
	
	public static void pke() throws Exception
	{
		/*
		 * pke method will call the following methods in PKE.java:
		 * 		-keyGen()
		 * 		-Enc()
		 * 		-Dec()
		 * These methods follow the Saber algorithms 
		 * and prints the generated matrices and vectors to an output .txt file.
		 * 
		 * pke method will also store:
		 * 		-cipher text, c
		 * 		-secret vector, s
		 * 		-recovered message m' 
		 * in hex to their corresponding .txt files
		 */
		Formatter pke = new Formatter("PKEOutput.txt");
		addToFile(pke,"\n************************************************************"
			   + "\n**************************KEYGEN****************************"
			   + "\n************************************************************");
		byte[] KeyGenRes = PKE.KeyGen();	// (PublicKeycpa||SecretKeycpa) 2240 bytes 
		byte[] PublicKeycpa = Arrays.copyOfRange(KeyGenRes, 0, 992);	//(seedA||b)
		byte[] SecretKeycpa = Arrays.copyOfRange(KeyGenRes, 992, KeyGenRes.length); 
		
		//store s in hex in file SecretKey.txt
		Formatter s = new Formatter("SecretKey.txt");
		addToFile(s,byteArrayToHex(SecretKeycpa));
		s.close();
		
		//Generate SeedS to generate s' in Encryption
		byte[] seedS = PKE.randomBytes(32);
		
		//read msg.txt to get message to encrypt
		String msg = readFile("msg.txt");
		
		BigInteger[] m= new BigInteger[PKE.n];
		for(int i=0; i<PKE.n;i++)
		{
			m[i]=BigInteger.valueOf(Character.getNumericValue(msg.charAt(i)));
		}
		
		//Write to PKEOutput file
		//addToFile(pke,"seedA: " + PKE.convertBytesToBinaryString(Arrays.copyOfRange(PublicKeycpa, 0, 32))); //32 bytes
		print(pke,PKE.BS2POLVEC(Arrays.copyOfRange(PublicKeycpa, 32, 992),ep),"b");
		print(pke,PKE.BS2POLVEC(SecretKeycpa, eq), "s");
		
		addToFile(pke,"************************************************************"
				   + "\n************************ENCRYPTION**************************"
				   + "\n************************************************************");
		
		addToFile(pke,"\n\nMessage to encrypt: \n ");
		print(pke,m, "m");
		
	
		//Encryption return 1088 bytes. (CipherTextcpa) =(cm||b)
		byte[] CipherTextcpa = PKE.Enc(m,seedS, PublicKeycpa);
		
		//Write to PKEOutput file
		print(pke,PKE.BS2POL(Arrays.copyOfRange(CipherTextcpa, 0, 128), et), "cm");	//128 bytes
		print(pke,PKE.BS2POLVEC(Arrays.copyOfRange(CipherTextcpa, 128, 1088), ep), "b'"); //960 bytes
		
		
		//store c in hex in file c.txt
		Formatter cm = new Formatter("c.txt");
		addToFile(cm,byteArrayToHex(Arrays.copyOfRange(CipherTextcpa,0,128)));
		cm.close();
		addToFile(pke,"************************************************************"
				   + "\n************************DECRYPTION**************************"
				   + "\n************************************************************\n");
		
		//Decryption returns recovered message 
		byte[] mdBytes =PKE. Dec(CipherTextcpa, SecretKeycpa);
		
		//store recovered message in hex in file recoveredMsg.txt
		Formatter RecMsg = new Formatter("recoveredMsg.txt");
		addToFile(RecMsg,byteArrayToHex(mdBytes));
		RecMsg.close();
		
		
		print(pke,PKE.BS2POL(mdBytes,1),"m'");
		

		String recoveredMsg= PKE.convertBytesToBinaryString(mdBytes);
		
		if(recoveredMsg.equals(msg.substring(0,recoveredMsg.length())))
		{
			System.out.println("Recovered message matches the original message");
		}
		else
		{
			System.out.println("Did not decrypt to original message");
		}
		
		pke.close();
	}
	
	public static void kem() throws Exception
	{
		/*
		 * key encapsulation mechanism
		 * KeyGen(), 
		 * Encaps(PublicKeycca) 
		 * and Decaps(CipherTextcca, SecretKeycca) 
		 * follows the KEM algorihtms outlined in Saber round 3 paper
		 * 
		 */
		
		Formatter kem = new Formatter("KEMOutput.txt");
		addToFile(kem,"\n\n************************************************************"
				   + "\n**************************KEYGEN****************************"
				   + "\n************************************************************\n");
		byte[] KeyGenRes = KEM.KeyGen(); //returns 3296 bytes 
		byte[] PublicKeycca = Arrays.copyOfRange(KeyGenRes, 0, 992); //992 bytes, (same as PKE.KeyGen public key)
		byte[] SecretKeycca = Arrays.copyOfRange(KeyGenRes, 992, 3296); //2304 bytes 
		
		print(kem,PKE.BS2POLVEC(Arrays.copyOfRange(PublicKeycca, 32, 992),ep),"Public Key cca, b");
		print(kem,PKE.BS2POLVEC(Arrays.copyOfRange(SecretKeycca, 1056, 2304), eq), "Secret Key cca, s");
		
		
		addToFile(kem,"\n************************************************************"
				   + "\n***********************ENCAPSULATION*************************"
				   + "\n************************************************************\n");
		byte[] EncRes =  KEM.Encaps(PublicKeycca);	//returns (SessionKeycca, CipherTextcca) 
		byte[] SessionKeycca = Arrays.copyOfRange(EncRes, 0, 32); //32 bytes
		String SessionKeyEncaps = (PKE.convertBytesToBinaryString(SessionKeycca)); //256 bits
		
		//write to output files
		addToFile(kem,"\nEncapsulation Session Key: "  +SessionKeyEncaps) ;

		byte[] CipherTextcca = Arrays.copyOfRange(EncRes, 32, 1120);
		print(kem,PKE.BS2POL(Arrays.copyOfRange(CipherTextcca, 0, 128),et),"Cm");
		print(kem,PKE.BS2POL(Arrays.copyOfRange(CipherTextcca, 128, 1120),ep),"b'");
		
		
		addToFile(kem,"\n************************************************************"
				   + "\n**********************DECAPSULATION*************************"
				   + "\n************************************************************\n");
		
		byte[] SessionKeycca2 =  KEM.Decaps(CipherTextcca, SecretKeycca);	//returns SessionKey 32 bytes
		
		String SessionKeyDecaps = (PKE.convertBytesToBinaryString(SessionKeycca2));
		
		//write binary string of session key to output file
		addToFile(kem,"\nDecapsulation Session Key: "  +SessionKeyDecaps+"\n") ;

		//print result
		if (SessionKeyEncaps.equals(SessionKeyDecaps)) 
		{
			System.out.println("\nSession Keys match");
			Formatter Session = new Formatter("SessionKey.txt");
			addToFile(Session, SessionKeyDecaps);
			Session.close();
		} else {
			System.out.println("\nSession Keys do not match");
		}
		kem.close();
	}
	
	
	public static String readFile(String fileName)
	{
		Scanner x;
		try 
		{
			x= new Scanner(new File(fileName));
			String m=x.nextLine();
			x.close();
			return m;
		}
		catch(Exception e) 
		{
			System.out.println(fileName+ " file not Found");
			System.exit(0);
			return null;
		}
	}

	
	public static void addToFile(Formatter x, String s)
	{
		x.format("%s", s);
	}
	
	//converys byte array to a hex string 
	public static String byteArrayToHex(byte[] barray)
	{
		String hexOutput = new String("");
		String hexStr= new String("");
		
		for(int i=0;i<barray.length;i++)
		{
			hexStr=byteToHex(barray[i]);
			hexOutput += hexStr;
			if(i<barray.length-1)
			{
				hexOutput+=":";
			}
		}
		return hexOutput;
	}
	
	//converts byte to its Hex value
	public static String byteToHex(byte data)
	{
		StringBuffer buf =new StringBuffer();
		buf.append(toHexChar((data>>>4)&0x0F));
		buf.append(toHexChar(data&0x0F));
		return buf.toString();
	}
	
	//converts int to a hex char
	public static char toHexChar (int i)
	{
		if((0<=i) && (i<=9))
		{
			return (char)('0'+i);
		}
		else
		{
			return (char)('A'+(i-10));
		}
	}
	
	
	
	//methods for printing to file x
	public static void print(Formatter x, BigInteger[] A, String s)
	{
		addToFile(x,"\n=============="+s+"=============\n");
		addToFile(x, "\n ( ");
		for(int i=0; i<n;i++)
		{
			addToFile(x, A[i]+"");
			if(i!= n-1)
			{
				addToFile(x," , ");
			}
		}
		addToFile(x," )   ");
		addToFile(x,"\n"+"\n");
	}
	
	
	public static void print(Formatter x,BigInteger[][] A, String s)
	{
		addToFile(x,"\n=============="+s+"=============\n");
		for(int i=0;i<l;i++)
		{
			addToFile(x,"\n ( ");
			for(int j=0; j<n; j++)
			{
				addToFile(x,A[i][j]+"");
				if(j!= n-1)
				{
					addToFile(x," , ");
				}
			}
			addToFile(x," )   ");
			
		}
		addToFile(x,"\n\n");
	}
	
	public static void print(Formatter x,BigInteger[][][] A, String s)
	{
		addToFile(x,"\n=============="+s+"=============\n");
		for(int i=0; i<l; i++)
		{
			addToFile(x,"\n"+" ");
			for(int j=0; j<l ;j++)
			{
				addToFile(x," ( ");
				for(int k=0;k<n;k++)
				{
					System.out.print (A[i][j][k].toString());
					if(k!= n-1)
					{
						addToFile(x," , ");
					}
				}
				addToFile(x," )   ");
			}
			addToFile(x," ");
			
		}
		addToFile(x,"\n");
	}
}
