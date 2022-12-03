package cipds9.uf1;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Genera hash
 * 
 * @author pererdg
 *
 */
public class Activitat7 {

	public static void main(String[] args) throws Exception {
		String[] missatges = {"El MessageDigest.digest serveix per obtenir el hash", 
				"Hola", "La Gamba de Palamós és la millor"};
		
		// SHA-1
		for ( String msg : missatges) {
			byte[] hash = getHash(msg, "SHA-1");
			System.out.println("Longitud del hash: " + hash.length*8);
			System.out.println(Arrays.toString(hash));
		}
		
		// SHA-256
		for ( String msg : missatges) {
			byte[] hash = getHash(msg, "SHA-256");
			System.out.println("Longitud del hash: " + hash.length*8);
			System.out.println(Arrays.toString(hash));
		}		
		cryptoLib();
	}
		
	private static void cryptoLib() throws Exception {
		System.out.println("-- CRYPTOLIB --");
		String[] missatges = {"El MessageDigest.digest serveix per obtenir el hash", 
				"Hola", "La Gamba de Palamós és la millor"};
		
		// SHA-256
		for ( String msg : missatges) {
			byte[] hash = Crypto.hashText(msg);
			System.out.println("Longitud del hash: " + hash.length*8);
			System.out.println(Arrays.toString(hash));
		}		

	}
	
	public static byte[] getHash(String dades, String algoritme) throws Exception {
		byte[] data = dades.getBytes(StandardCharsets.UTF_8);
		MessageDigest md = MessageDigest.getInstance(algoritme);
		return md.digest(data);
	}	
}