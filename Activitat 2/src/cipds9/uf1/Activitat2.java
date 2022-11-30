package cipds9.uf1;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Activitat2 {

	public static void main(String[] args) throws Exception {
		int keySize[] = {128, 192, 256};
		for (int size : keySize) {
			SecretKey sk = generateKey("hola123444t643233232322332", size);
			System.out.println("Longitud de la clau: " + sk.getEncoded().length*8);
			System.out.println(Arrays.toString(sk.getEncoded()));
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

}
