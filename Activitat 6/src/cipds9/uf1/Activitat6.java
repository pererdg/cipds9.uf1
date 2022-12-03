package cipds9.uf1;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Intenta descobrir un text xifrat i la contrasenya donades algunes dades
 * d'unt text xifrat amb AES/ECB.
 * 
 * @author perer
 *
 */
public class Activitat6 {

	public static void main(String[] args) throws Exception {
		// Text xifrat
		byte[] tx = {99, -63, 114, -69, -56, 13, -10, -27, -94, 64, -86, 126, -91, 30, -8, -37, -106, -101, 78, 56, -96, 1, 25, 9, 71, -25, 28, -48, 108, -35, -110, 69, -23, 16, -103, 3, 21, -75, -44, -20, -123, -122, -78, -82, -74, 61, -13, -57, -78, 114, 41, 111, 44, 96, 28, 83, 36, 98, -29, -41, 49, 125, 58, -69};
		
		// Desxifrar
		for (int n=0; n<10000; n++) {
			String pwd = "000" + Integer.toString(n);
			pwd = pwd.substring(pwd.length()-4);
			SecretKey key = generateKey(pwd, 256);
			try {
				String td = desxifrarText(key, tx);
				System.out.println(pwd + " >> " + td);
			} catch (Exception e) {}
		}
	}
	
	/**
	 * Genera una clau simètrica a partir d'un password
	 * @param pwd Contrasenya 
	 * @param keySize Longitud de la clau, màxim 256
	 * @return Clau generada (SecretKey)
	 * @throws Exception
	 */
	public static SecretKey generateKey(String pwd, int keySize) throws Exception {
		byte[] data = pwd.getBytes(StandardCharsets.UTF_8);
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] hash = md.digest(data);
		byte[] key = Arrays.copyOf(hash, keySize/8);
		return new SecretKeySpec(key, "AES");
	}

	/**
	 * Desxifra text que ha estat xifrat amb AES/ECB
	 * 
	 * @param sKey Clau simètrica
	 * @param data Text xifrat
	 * @return Text desxifrat
	 * @throws Exception
	 */
	public static String desxifrarText(SecretKey sKey, byte[] data) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, sKey);
		return new String(cipher.doFinal(data), StandardCharsets.UTF_8);
	}
	
}
