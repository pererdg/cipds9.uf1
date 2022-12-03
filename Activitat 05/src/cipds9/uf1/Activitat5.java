package cipds9.uf1;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Xifra i desxifra amb AES/CBC/PKCS5Padding
 * Retalla el text xifrat treient els primers 16 bytes i llavors desxifra.
 * 
 * @author pererdg
 *
 */
public class Activitat5 {
	
	public static final byte[] IV = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF};

	public static void main(String[] args) throws Exception {
		String text = "la criptografia és molt més fàcil del que sembla";
		System.out.println("Bytes text desxifrat: \n" + Arrays.toString(text.getBytes(StandardCharsets.UTF_8)));
		
		// Xifrar
		SecretKey key = generateKey("hola", 256);
		byte[] tx = xifrarText(key, text);
		
		System.out.println("Bytes text xifrat: \n" + Arrays.toString(tx));
		
		// Desxifrar
		String td = desxifrarText(key, tx);
		System.out.println("Text desxifrat: \n" + td);

		// Retallar 16 bytes al principi del text xifrat
		byte[] txr = Arrays.copyOfRange(tx, 16, tx.length);
		td = desxifrarText(key, txr);
		System.out.println("Bytes text desxifrat retallat: \n" + Arrays.toString(td.getBytes(StandardCharsets.UTF_8)));
		System.out.println("Text desxifrat retallat: \n" + td);
		cryptoLib();
	}
	
	private static void cryptoLib() throws Exception {
		System.out.println("-- CRYPTOLIB --");
		String text = "la criptografia és molt més fàcil del que sembla";
		System.out.println("Bytes text desxifrat: \n" + Arrays.toString(text.getBytes(StandardCharsets.UTF_8)));
		
		// Xifrar
		SecretKey key = CryptoSym.generateKey(256, "hola");
		byte[] tx = CryptoSym.encryptText(key, text);
		
		System.out.println("Bytes text xifrat: \n" + Arrays.toString(tx));
		
		// Desxifrar
		String td = CryptoSym.decryptText(key, tx);
		System.out.println("Text desxifrat: \n" + td);

		// Retallar 16 bytes al principi del text xifrat
		byte[] txr = Arrays.copyOfRange(tx, 16, tx.length);
		td = CryptoSym.decryptText(key, txr);
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

	/**
	 * Xifra text amb AES/CBC
	 * 
	 * @param sKey Clau simètrica
	 * @param frase Text a xifrar
	 * @return Text xifrat
	 * @throws Exception
	 */
	public static byte[] xifrarText(SecretKey sKey, String frase) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, sKey, new IvParameterSpec(IV));
		return cipher.doFinal(frase.getBytes(StandardCharsets.UTF_8));
	}
	
	/**
	 * Desxifra text que ha estat xifrat amb AES/CBC
	 * 
	 * @param sKey Clau simètrica
	 * @param data Text xifrat
	 * @return Text desxifrat
	 * @throws Exception
	 */
	public static String desxifrarText(SecretKey sKey, byte[] data) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, sKey, new IvParameterSpec(IV));
		return new String(cipher.doFinal(data), StandardCharsets.UTF_8);
	}
}
