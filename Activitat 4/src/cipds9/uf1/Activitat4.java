package cipds9.uf1;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Activitat4 {

	public static void main(String[] args) throws Exception {
		String text = "la criptografia és molt més fàcil del que sembla";
		System.out.println("Bytes text desxifrat: \n" + Arrays.toString(text.getBytes(StandardCharsets.UTF_8)));
		
		// Xifrar
		SecretKey key = generateKey("hola", 256);
		byte[] tx = xifraText(key, text);
		
		System.out.println("Longitud bytes text desxifrat " + text.getBytes().length);
		System.out.println("Longitud bytes text xifrat " + tx.length);
		System.out.println("Bytes text xifrat: \n" + Arrays.toString(tx));
		
		// Desxifrar
		String td = desxifraText(key, tx);
		System.out.println("Bytes text desxifrat: \n" + Arrays.toString(td.getBytes(StandardCharsets.UTF_8)));
		System.out.println("Text desxifrat: \n" + td);

		// Retallar 16 bytes al principi del text xifrat
		byte[] txr = Arrays.copyOfRange(tx, 32, tx.length);
		td = desxifraText(key, txr);
		System.out.println("Bytes text desxifrat retallat: \n" + Arrays.toString(td.getBytes(StandardCharsets.UTF_8)));
		System.out.println("Text desxifrat retallat: \n" + td);
		
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

	public static byte[] xifraText(SecretKey sKey, String frase) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, sKey);
		return cipher.doFinal(frase.getBytes(StandardCharsets.UTF_8));
	}
	
	public static String desxifraText(SecretKey sKey, byte[] data) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, sKey);
		return new String(cipher.doFinal(data), StandardCharsets.UTF_8);
	}
	
}
