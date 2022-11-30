package cipds9.uf1;

import java.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Activitat1 {

	public static void main(String[] args) throws Exception {
		int keySize[] = {128, 192, 256};
		for (int size : keySize) {
			SecretKey sk = generateKey(size);
			System.out.println("Longitud de la clau: " + sk.getEncoded().length*8);
			System.out.println(Arrays.toString(sk.getEncoded()));
		}
	}
	
	/**
	 * Genera una clau simètrica de la mida seleccionada
	 * @param keySize Mida de la clau 128 | 192 | 256
	 * @return Clau generada (SecretKey)
	 * @throws Exception
	 */
	public static SecretKey generateKey(int keySize) throws Exception {
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		kgen.init(keySize);
		return kgen.generateKey();
	}

}
