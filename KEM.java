import java.math.BigInteger;
import java.util.Arrays;
import java.security.MessageDigest;
import java.io.ByteArrayOutputStream;

public class KEM {
	
	//Saber constants
	public static int l = 3;
	public static int n = 256;
	public static int eq = 13;
	public static int ep = 10;
	public static int et = 4;
	public static int u = 8;
	public static BigInteger two = BigInteger.valueOf(2);
	public static BigInteger four = BigInteger.valueOf(4);
	public static BigInteger eight = BigInteger.valueOf(8);


	public static byte[] KeyGen() throws Exception 
	{
		// (PublicKeycpa, SecretKeycpa) = PKE.KeyGen()
		byte[] PKEKeyGenRes = PKE.KeyGen();
		byte[] PublicKeycpa = Arrays.copyOfRange(PKEKeyGenRes, 0, 992);
		byte[] SecretKeycpa = Arrays.copyOfRange(PKEKeyGenRes, 992, 2240);

	
		byte[] hash_pk = SHA3_256(PublicKeycpa, 992);
		byte[] z = PKE.randomBytes(32);

		ByteArrayOutputStream secretKeycca = new ByteArrayOutputStream();
		secretKeycca.write(z);
		secretKeycca.write(hash_pk);
		secretKeycca.write(PublicKeycpa);
		secretKeycca.write(SecretKeycpa);
		byte[] SecretKeycca = secretKeycca.toByteArray();
		//SecretKeycca = (z || hash_pk || PublicKeycpa || SecretKeycpa )
		
		byte[] PublicKeycca = PublicKeycpa;

		ByteArrayOutputStream output = new ByteArrayOutputStream();
		output.write(PublicKeycca);
		output.write(SecretKeycca);
		byte[] Output = output.toByteArray();
		// Output = ( PublicKeycca || SecretKeycca )
		
		return Output;
		
		/*
		 *  returns (PublicKeycca, SecretKeycca), 3296 bytes 
		 *  PublicKey cca, 992 bytes
		 *  	seedA, 32 bytes
		 *  	b, 960 bytes
		 *  SecretKey cca, 2304 bytes
		 * 
		 */
	}

	public static byte[] Encaps(byte[] PublicKeycca) throws Exception 
	{
		byte[] m = PKE.randomBytes(32);
		m = SHA3_256(m, 32);
		byte[] hash_pk = SHA3_256(PublicKeycca, 992);

		ByteArrayOutputStream buf = new ByteArrayOutputStream();
		buf.write(hash_pk);
		buf.write(m);
		byte[] Buf = buf.toByteArray();
		//Buf = (hash_pk || m )

		byte[] kr = SHA3_512(Buf, 32 * 2); // ( r || k )
		byte[] r = Arrays.copyOfRange(kr, 0, 32);
		byte[] k = Arrays.copyOfRange(kr, 32, 64);

		//CipherTextcca = PKE.Enc(m,r,PublicKeycca)
		byte[] CipherTextcca = PKE.Enc(PKE.BS2POL(m, 1), r, PublicKeycca);

		//r' = SHA3-256(CipherTextcca, 1088)
		byte[] rd = SHA3_256(CipherTextcca, 1088); 

		ByteArrayOutputStream krdtemp = new ByteArrayOutputStream();
		krdtemp.write(rd);
		krdtemp.write(k);
		byte[] krd = krdtemp.toByteArray();
		// kr' = ( r' || k ) 

		byte[] SessionKeycca = SHA3_256(krd, 32 * 2);

		ByteArrayOutputStream output = new ByteArrayOutputStream();
		output.write(SessionKeycca);
		output.write(CipherTextcca);
		byte[] Output = output.toByteArray();
		
		// Output = (SessionKeycca || CipherTextcca )

		return Output;
		/*
		 * Returns (SessionKeycca, CipherTextcca), 1120 bytes
		 * 	SessionKeycca, 32 bytes
		 * 	CipherTextcca, 1088 bytes
		 * 		cm,  128 bytes
		 * 		b, 960 bytes 
		 */
	}

	public static byte[] Decaps(byte[] CipherTextcca, byte[] SecretKeycca) throws Exception 
	{
		//Extract ( z || hash_pk || PublicKeycpa || SecretKeycpa ) from SecretKeycca
		byte[] z = Arrays.copyOfRange(SecretKeycca, 0, 32);
		byte[] hash_pk = Arrays.copyOfRange(SecretKeycca, 32, 64);
		byte[] PublicKeycpa = Arrays.copyOfRange(SecretKeycca, 64, 1056);
		byte[] SecretKeycpa = Arrays.copyOfRange(SecretKeycca, 1056, 2304);

		//recovered message from PKE decryption
		byte[] m = (PKE.Dec(CipherTextcca, SecretKeycpa));

		ByteArrayOutputStream buf = new ByteArrayOutputStream();
		buf.write(hash_pk);
		buf.write(m);
		byte[] Buf = buf.toByteArray();
		//Buf = (hash_pk || m)
		

		byte[] kr = SHA3_512(Buf, 32 * 2);	// kr = ( r|| k )  64 bytes 
		byte[] r = Arrays.copyOfRange(kr, 0, 32);	
		byte[] k = Arrays.copyOfRange(kr, 32, 64);
		
		
		//PKE Enc returns 1088 bytes
		//CipherText'cca = PKE.Enc(m,r,PublicKeycpa)
		byte[] CipherTextccad = PKE.Enc(PKE.BS2POL(m, 1), r, PublicKeycpa);
		
		//Check if CipherTextcca' quals CipherTextcca.
		//If equal, c = 1, else c=0.
		int c = Verify(CipherTextccad, CipherTextcca, 1088);

		byte[] rd = SHA3_256(CipherTextccad, 1088);

		ByteArrayOutputStream temp = new ByteArrayOutputStream();
		if (c == 1) {
			temp.write(rd);
			temp.write(k);
			// temp = ( r' || k )
		} else {
			temp.write(rd);
			temp.write(z);
			// temp = ( r' || z )
		}

		byte[] Temp = temp.toByteArray();
		byte[] SessionKeycca = SHA3_256(Temp, 32 * 2);

		return SessionKeycca;

	}

	//Check if two byte arrays are the same. Return 1 if same, else return 0;
	public static int Verify(byte[] BS1, byte[] BS2, int len) {
		if (BS1.length != BS2.length)
			return 0;
		if (Arrays.equals(BS1, BS2)) {
			return 1;
		} else
			return 0;
	}

	public static byte[] SHA3_256(byte[] seed, int len) throws Exception 
	{
		//return FIPS202.HashFunction.SHA3_256.apply(len, seed);
		
		MessageDigest digest = MessageDigest.getInstance("SHA3-256");
		byte[] encodedhash = digest.digest(seed);
		return encodedhash;
		
	}

	public static byte[] SHA3_512(byte[] seed, int len) throws Exception
	{
		//return FIPS202.HashFunction.SHA3_512.apply(len, seed);
		MessageDigest digest = MessageDigest.getInstance("SHA3-512");
		byte[] encodedhash = digest.digest(seed);
		return encodedhash;
	}
}
