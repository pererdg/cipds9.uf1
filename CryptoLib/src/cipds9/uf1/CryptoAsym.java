package cipds9.uf1;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 * Llibreria de funcions de criptografia asimètrica
 * 
 * @author pererdg
 * @version 1
 *
 */
public abstract class CryptoAsym {
	
	public static final int KEY_LENGTH = 2048;
	public static final String ALGORITHM = "RSA";
	public static final String CIPHER_INSTANCE = "RSA/ECB/PKCS1Padding";
	public static final String SIGN_INSTANCE = "SHA256withRSA"; 
	
	/**
	 * Genera clau pública i privada {@value #ALGORITHM} de longitud {@value #KEY_LENGTH} bits
	 * 
	 * @return Clau generada (KeyPair)
	 * @throws Exception
	 */
	public static KeyPair generateKey() throws Exception {
		return generateKey(KEY_LENGTH);
	}
	
	/**
	 * Genera clau pública i privada {@value #ALGORITHM}
	 * 
	 * @param keySize Longitud de la clau en bits
	 * @return Clau generada (KeyPair)
	 * @throws Exception
	 */
	public static KeyPair generateKey(int keySize) throws Exception {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
		keyGen.initialize(keySize);
		return keyGen.genKeyPair();
	}

	/**
	 * Xifra dades amb xifratge híbrid {@value CryptoSym#CIPHER_INSTANCE} - {@value #CIPHER_INSTANCE} 
	 * 
	 * @param pub Clau pública
	 * @param data Dades a xifrar
	 * @return Dades i clau simètrica xifrats (byte[][] [0] dades xifrades, [1] clau simètrica xifrada)
	 * @throws Exception
	 */
	public static byte[][] encrypt(PublicKey pub, byte[] data) throws Exception {
		byte[][] wrap = new byte[2][];

		// Xifrar text amb AES
		SecretKey sk = CryptoSym.generateKey();
		wrap[0] = CryptoSym.encrypt(sk, data);

		// Xifrar clau amb RSA
		Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);
		cipher.init(Cipher.WRAP_MODE, pub);
		wrap[1] = cipher.wrap(sk);
		return wrap;
	}
	
	/**
	 * Xifra text amb xifratge híbrid {@value CryptoSym#CIPHER_INSTANCE} - {@value #CIPHER_INSTANCE}
	 * 
	 * @param pub Clau pública
	 * @param text Text a xifrar
	 * @return Text i clau simètrica xifrats (byte[][] [0] text xifrat, [1] clau simètrica xifrada)
	 * @throws Exception
	 */
	public static byte[][] encryptText(PublicKey pub, String text) throws Exception {
		return encrypt(pub, text.getBytes("UTF-8"));
	}
	
	/**
	 * Xifra dades amb xifratge directe {@value #CIPHER_INSTANCE} 
	 * 
	 * @param pub Clau pública
	 * @param data Dades a xifrar
	 * @return Dades xifrades
	 * @throws Exception
	 */
	public static byte[] encryptDirect(PublicKey pub, byte[] data) throws Exception {
		// Xifrar clau amb RSA
		Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);
		cipher.init(Cipher.ENCRYPT_MODE, pub);
		return cipher.doFinal(data);
	}
	
	/**
	 * Desxifra dades xifrades amb xifratge híbrid {@value CryptoSym#CIPHER_INSTANCE} - {@value #CIPHER_INSTANCE} 
	 * 
	 * @param priv Clau privada
	 * @param wrap Dades xifrades: [0] dades xifrades, [1] clau simètrica xifrada
	 * @return Dades desxifrades (byte [])
	 * @throws Exception
	 */
	public static byte[] decrypt(PrivateKey priv, byte[][] wrap) throws Exception {
		// Desxifrar clau simètrica amb RSA
		Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);
		cipher.init(Cipher.UNWRAP_MODE, priv);
		SecretKey sKey = (SecretKey) cipher.unwrap(wrap[1], CryptoSym.ALGORITHM, Cipher.SECRET_KEY);

		// Desxifrar dades
		return CryptoSym.decrypt(sKey, wrap[0]);
	}
	
	/**
	 * Desxifra text xifrat amb xifratge híbrid {@value CryptoSym#CIPHER_INSTANCE} - {@value #CIPHER_INSTANCE} 
	 * 
	 * @param priv Clau privada
	 * @param wrap Dades xifrades: [0] text xifrat, [1] clau simètrica xifrada
	 * @return Text desxifrat (String)
	 * @throws Exception
	 */
	public static String decryptText(PrivateKey priv, byte[][] wrap) throws Exception {
		return new String(decrypt(priv,wrap), "UTF-8");
	}

	/**
	 * Xifra dades xifrades amb xifratge directe {@value #CIPHER_INSTANCE} 
	 * 
	 * @param priv Clau privada
	 * @param data Dades xifrades
	 * @return Dades desxifrades (byte [])
	 * @throws Exception
	 */
	public static byte[] decryptDirect(PrivateKey priv, byte[] data) throws Exception {
		// Desxifrar amb clau RSA
		Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);
		cipher.init(Cipher.DECRYPT_MODE, priv);
		return cipher.doFinal(data);
	}

	/**	Signa dades amb {@value #SIGN_INSTANCE}
	 * 
	 * @param priv Clau privada
	 * @param data Dades a signar
	 * @return Dades signades (byte[])
	 * @throws Exception
	 */
	public static byte[] sign(PrivateKey priv, byte[] data) throws Exception {
		Signature signer = Signature.getInstance(SIGN_INSTANCE);
		signer.initSign(priv);
		signer.update(data);
		return signer.sign();
	}

	/**	Signa text amb {@value #SIGN_INSTANCE}
	 * 
	 * @param priv Clau privada
	 * @param text Text a signar
	 * @return Text signat (byte[])
	 * @throws Exception
	 */
	public static byte[] signText(PrivateKey priv, String text) throws Exception {
		return sign(priv, text.getBytes("UTF-8"));
	}
	
	
	/**
	 * Valida signatura de dades feta amb {@value #SIGN_INSTANCE}
	 * 
	 * @param pub Clau pública
	 * @param data Dades no xifrades
	 * @param signature Signatura
	 * @return True/false
	 * @throws Exception
	 */
	public static boolean verifySign(PublicKey pub, byte[] data, byte[] signature) throws Exception {
		Signature signer = Signature.getInstance(SIGN_INSTANCE);
		signer.initVerify(pub);
		signer.update(data);
		return signer.verify(signature);
	}
	
	/**
	 * Valida signatura de text feta amb {@value #SIGN_INSTANCE}
	 * 
	 * @param pub Clau pública
	 * @param text Text pla
	 * @param signature Signatura
	 * @return True/false
	 * @throws Exception
	 */
	public static boolean verifySignText(PublicKey pub, String text, byte[] signature) throws Exception {
		return verifySign(pub, text.getBytes("UTF-8"), signature);
	}
}
