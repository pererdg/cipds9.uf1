package cipds9.uf1;

import java.security.MessageDigest;
import java.util.Base64;

/**
 * Llibreria de funcions de criptografia
 * 
 * @author pererdg
 * @version 1
 *
 */
public abstract class Crypto {
	
	public static final String HASH_ALGORITHM = "SHA-256";
	
	/**
	 * Calcula hash {@value #HASH_ALGORITHM}
	 * 
	 * @param data Dades
	 * @return hash (byte [])
	 * @throws Exception
	 */
	public static byte[] hash(byte[] data) throws Exception {
		MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);
		return md.digest(data);
	}
	
	/**
	 * Calcula hash {@value #HASH_ALGORITHM} d'un text
	 * 
	 * @param text Texte
	 * @return hash (byte [])
	 * @throws Exception
	 */
	public static byte[] hashText(String text) throws Exception {
		return hash(text.getBytes("UTF-8"));
	}
	
	/**
	 * Codifica a base 64
	 * 
	 * @param data Dades
	 * @return Dades codificades a base 64 (String)
	 */
	public static String encodeBase64(byte[] data) {
		return Base64.getEncoder().encodeToString(data);
	}
	
	/**
	 * Decodifica base 64
	 * 
	 * @param data Dades
	 * @return Dades descodificades (byte[])
	 */
	public static byte[] decodeBase64(String data) {
		return Base64.getDecoder().decode(data);
	}
}
