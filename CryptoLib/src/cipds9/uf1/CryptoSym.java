package cipds9.uf1;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Llibreria de funcions de criptografia simètrica
 * 
 * @author pererdg
 * @version 1
 *
 */
public abstract class CryptoSym {

	public static final IvParameterSpec IV = new IvParameterSpec(new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF});
	public static final int KEY_LENGTH = 256;
	public static final String ALGORITHM = "AES";
	public static final String CIPHER_INSTANCE = "AES/CBC/PKCS5Padding";
	
	/**
	 * Genera una clau simètrica {@value #ALGORITHM} de {@value #KEY_LENGTH} bits aleatòria
	 * 
	 * @return Clau generada (SecretKey)
	 * @throws Exception
	 */
	public static SecretKey generateKey() throws Exception {
		return generateKey(KEY_LENGTH);
	}
	
	/**
	 * Genera una clau simètrica {@value #ALGORITHM} aleatòria
	 * 
	 * @param keySize Mida de la clau en bits 128 | 192 | 256
	 * @return Clau generada (SecretKey)
	 * @throws Exception
	 */
	public static SecretKey generateKey(int keySize) throws Exception {
		KeyGenerator kgen = KeyGenerator.getInstance(ALGORITHM);
		kgen.init(keySize);
		return kgen.generateKey();
	}

	/**
	 * Genera una clau simètrica {@value #ALGORITHM} a partir d'un password
	 * 
	 * @param pwd Contrasenya 
	 * @param keySize Longitud de la clau en bits 128 | 192 | 256
	 * @return Clau generada (SecretKey)
	 * @throws Exception
	 */
	public static SecretKey generateKey(int keySize, String pwd) throws Exception {
		byte[] data = pwd.getBytes(StandardCharsets.UTF_8);
		byte[] key = Arrays.copyOf(Crypto.hash(data), keySize/8);
		return new SecretKeySpec(key, ALGORITHM);
	}

	/**
	 * Xifra dades amb {@value #CIPHER_INSTANCE}
	 * 
	 * @param sKey Clau simètrica
	 * @param data Dades a xifrar
	 * @return Dades xifrades (array de bytes)
	 * @throws Exception
	 */
	public static byte[] encrypt(SecretKey sKey, byte[] data) throws Exception {
		Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);
		cipher.init(Cipher.ENCRYPT_MODE, sKey, IV);
		return cipher.doFinal(data);
	}
	
	/**
	 * Xifra text amb {@value #CIPHER_INSTANCE}
	 * 
	 * @param sKey Clau simètrica AES
	 * @param text Text a xifrar
	 * @return Text xifrat (array de bytes)
	 * @throws Exception
	 */
	public static byte[] encryptText(SecretKey sKey, String text) throws Exception {
		return encrypt(sKey, text.getBytes("UTF-8"));
	}
	
	/**
	 * Desxifra dades xifrades amb {@value #CIPHER_INSTANCE}
	 * IMPORTANT: Les dades han d'haver estat xifrades per CryptoSym.encrypt 
	 * perquè el vector d'inicialització està fixat a la classe.
	 * 
	 * @param sKey Clau simètrica
	 * @param data Dades xifrades
	 * @return Dades desxifrades (array de bytes)
	 * @throws Exception
	 */
	public static byte[] decrypt(SecretKey sKey, byte[] data) throws Exception {
		Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);
		cipher.init(Cipher.DECRYPT_MODE, sKey, IV);
		return cipher.doFinal(data);
	}

	/**
	 * Desxifra text xifrat amb {@value #CIPHER_INSTANCE}
	 * 
	 * @param sKey Clau simètrica
	 * @param text Text xifrat
	 * @return Text desxifrat (string)
	 * @throws Exception
	 */
	public static String decryptText(SecretKey sKey, byte[] text) throws Exception {
		return new String(decrypt(sKey, text), "UTF-8");
	}
}
