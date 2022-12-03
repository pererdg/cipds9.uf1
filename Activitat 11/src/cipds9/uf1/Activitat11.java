package cipds9.uf1;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Valida la signatura de l'activitat 10
 *
 * Activitat 8 - POSSIBLE SORTIDA EN BASE 64
 * Clau privada: MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCuqr/QBx3975kYvdgwCk3Vh5lGMVwI3chqbEuEuU8vqbbZKlKe71jPVJFjz0O8r9TaSBARxxSsfoiBQq08GfBEekEFSQUqBbbd4KSRs9bRkdvE0BVd80eQHy3FwafgGulDdHhgPHtSUDvrs39+0GjmWeyVQhVT960jdO9uUPquewCk5vwjPhgmTxnNbbtreb/4xKWkWNjSURrEjaRpaqahlmmPQSqN6GB48VV+A9vdcLwrDB1P74udILCZ+ulfuyx/JxwKGAZFYjDzopZazGHMFVjxzEed9cnKIFGDSj704SPGIK1a5QrQinkmUtxELc5QCcfrCGoQavwyB2YvSuUBAgMBAAECggEAAP9JEOiLAtpViVVo5bqgpDghM5c1rDp+Mz/CU1dTDfSVLDUTeDcVse7rpLdL4YrxRq8an8MVX6ii+BDIYQRIYJFc+leIB32Wf9C0pZ40f4BxOY0hcNuFduANLYMpCgWENTEq1wND3mSEKzNNBUJNXX/ugBXkstkfBUmfAqLSA7VAWeGLr1QgLAB9nTA32jh5kGFO9cOzbdXT0vl0pXOWfWw+jQDNdqyTIJ21k8g3MsQpwijxO82COpQwC/qt8WNGduXm8jSi2nZ+WU01ih8fGAgxbuBpEJTafgQCTJ060Nxb89NJQLEz3VykUy6YGC1D4bDPhNqkTXpjRkaXV/YrFQKBgQDoi89JqQVpWJZVwN9e++FPMSZXQVR10GM+UJbLTks53JVQGWp7cfqtKCEq94BvRnK0wQWWCMfxljQwuPnXUwtL5uLb2tT/ngfIdC+Ofjo4wehoC08QS++oMGokWS8YYXGQ+4ftk6Oct2sLMXUogsm6291E0TB0dNIfQXUQ3xDnjQKBgQDASImijkNt1IFqFEGJ2kzZWRu8HstlRvaX8HSA5Zh1+CcMg/V+1h1dMHMH5yfbKINsdaGoyHvuK4Oz4BswHqs5dmbirWdUlXrrDyktBKg2uYoXeuOUDsB22StsfereXfj/7fJRrHABM9rXV6PGg95OUBG1coyApxqfNA5zQIFsRQKBgQCLrfbLkue6OEjMp3ZEMl1KWQZjoM0fmxURiAybf6K11aYmH64TCgp9Wb5adaHCtPkPU2WMkievF/6vSVxglvQRGlUno9EO3RhlskwidfV4xBhZ7nkGG+aPCs2mmZ8tMNKrODqUXHsJFi8I4SMzOyP6xjepL1HAka7osUOk56favQKBgFuteioOKGoiSv3X4JOoiMGMcePUzudf2U0CMZoPXgzJH10hQZiS3/dBlWbsOJ2OiHLa9xPxWt1o0+ecb3oW9U51fIKRaNX0W2HdnaVANi+5cPTW+9Do460GyGR2+NfC+GiV+9YjIFgCcFICEC0jTIgMNxVLI2BnzBKiEE21ML/9AoGAEpGtG674r6pN8CYLOBGMks+jg65NJK4uE659nv75CTyIOxHtNhkarVUnbhNfUX+/eSnZDSLXCPMKjh9vRbmmyeqFPjbatYTV0jA9t5qctMHb83hupXQ5PanJ3wYCt/rrEZABEJNIcjWJO0G+Mgw5iagxM2FwtwXCXRWtdAbzIhg=
 * Clau pública: MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArqq/0Acd/e+ZGL3YMApN1YeZRjFcCN3IamxLhLlPL6m22SpSnu9Yz1SRY89DvK/U2kgQEccUrH6IgUKtPBnwRHpBBUkFKgW23eCkkbPW0ZHbxNAVXfNHkB8txcGn4BrpQ3R4YDx7UlA767N/ftBo5lnslUIVU/etI3TvblD6rnsApOb8Iz4YJk8ZzW27a3m/+MSlpFjY0lEaxI2kaWqmoZZpj0EqjehgePFVfgPb3XC8KwwdT++LnSCwmfrpX7ssfyccChgGRWIw86KWWsxhzBVY8cxHnfXJyiBRg0o+9OEjxiCtWuUK0Ip5JlLcRC3OUAnH6whqEGr8MgdmL0rlAQIDAQAB
 * Wrapped text: k5F1BLthZbBR5vqvvHoWc3yiYxDJUlgiGVm3mlMcinEuVY/VXeybSUa2szbVrclruNGZHMieXEkvAq6xz/1rHkkC0q4/TT/ltcGrQs94P1BirhxSFobFJzG1x+lQTavD57w+1FY42IfuHapDm+S2M42VnQMeD3IUZ4FftJFhKumTR+1g+y72GCMCBDKRs4Iq6IbNnoz47njVdTucR4TR8J21pMKF2V6uXFEKgela7+o4ZdbYSKBttWDmCrUpoOb+jnuBdfr93KkNlpQ2bevSyNzwGiaOjOh0KSpxJNBRiVE/hnD71hZ7NuxiZKK0GmMN9NlHewS1G2spOtwjfhSk6xur0UV0gGIUYm/ItkXiSf0at5PvYcfCs+pOjirsnSZrZR4SWO6H9TJdldEyDj6V4x5Uar2NpHUpZTrOMhxyWUZklUI5vu9Fj6JU5jG938Ja61AJjNDNkX/EbQL9vws3/sleGiRVgW7Gi1D9AYCNMOnaLPoHUBMJzYehhRQZ9tKm1zkbFupU3KyZjirHCjLckSLf9EX/+htEqpNTRkQAc94C+UEXk7WWrOwThvcFdh+3c+WKNcVX1pjv8I0E2zgXILzqXKTzH3wERIxWXG68bUE=
 * Wrapped clau simètrica: NKGEUBtKD2ehEJMyCgyndCzaOJkjxitVEV9UXK1Lt6s9x2cZyWJOM/tRci/0smViZLriVHpFtPdMDTZOmtLGsp6Txoj8Fw6yThBlAY5aoWskrI26pqXBYLP5Ii9J7dEfVZUvRmD74jVlx8+G1NpHHpVrMueOr2Gqg84ZKv1ac59gXFvdRdFQGVX8ZTeb1PFLMLNbPgSInulyFSA5hIbQjYcuRtYuu8FnX9TvFokc7i8rZJ5VY6Nq/qqLwgCDhPlbWUKpkb9V4m5oJb+un/yeAZY7fwfpO95qqD/abIMTigH8s4uz49S+fNRjFa/ZUn3XO3nbC2mNcVVb4oppLW5JNw==
 * 
 * Activitat 8 - POSSIBLE SORTIDA EN BASE 64 (CRYPTOLIB)
 * Clau pública: MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzGt5SimdRBlyZKri79UQk2MXVZ4sx9OXaMpM4+RGo5ghHK2LTPJY85yggQOr6b1OfaSCwEH3JpY8o0zkiQS5iJA92/IbNEf/vebMfxbHp24T5NV6irHBWjbZ1nvCMoTBrbcSHzXljmpMKSJbl2FZKWrghF7OLT4ZvIUvzlFlYiGDdXSl4Gw/WJKhiIxGun/cxIKTSVY7GqPeXao2sxvy/585wJKpHwRPPZMhYGJgq8OSD9AyNaOzFwW6XTdOgnu0xIr4u+2oSGsw3/uzOefT80s+yJBXIwfDHRpm2RcGlhUVd60w7u9uhuuFm5RdUkQQhxy5EsqKM0m2w9s8p7LewIDAQAB
 * Clau privada: MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7Ma3lKKZ1EGXJkquLv1RCTYxdVnizH05doykzj5EajmCEcrYtM8ljznKCBA6vpvU59pILAQfcmljyjTOSJBLmIkD3b8hs0R/+95sx/FsenbhPk1XqKscFaNtnWe8IyhMGttxIfNeWOakwpIluXYVkpauCEXs4tPhm8hS/OUWViIYN1dKXgbD9YkqGIjEa6f9zEgpNJVjsao95dqjazG/L/nznAkqkfBE89kyFgYmCrw5IP0DI1o7MXBbpdN06Ce7TEivi77ahIazDf+7M559PzSz7IkFcjB8MdGmbZFwaWFRV3rTDu726G64WblF1SRBCHHLkSyoozSbbD2zynst7AgMBAAECggEAB8oGaV2qp35aLewLdVItyGB/sbaSaSmpUh4i7cFQkWFRRNGdIP5hp+SEQUK39bklxRasdwbA8/38K4OSnMchfi/4shMVrOl6wlo9O/Q7Omfnrm/8CDVleKUnVAKa/quh5Qqg2edP9TFLB/ogudXsYga+vzfI/9AP8gCqulZAvfsQ4syCA0dpBgOdSXbYgJJctqhboufoRWvW2zpoRoJQlQBXfajmpd6ve4pCcK85d014/QwTIkC8hfoqwOVxp5psYxxVaZ0LwXDr3NCQbuac+vg5VfSrBnyNdDb2fM6vnwPt3RBekt6yL2ZHiW/3ykqp4QKDq6g6xqpsezXTdL0sYQKBgQD+9wqA9zvRvk4IhNs/UPciLa/cg7uCTJK4Bsih8zA50mP4o446sF7AegB06Dg4FvtAjBDHXCwcL6F00iloTW0FO9wpDtmwUB0DVKS9vpNLcGFpFlzbFOBDunYJhgmGx2u5kglsrzJYjnietpQ5IO4x8HBD5PRUcI+4qEgblqVYEQKBgQC79DX6z4v4FW6h2FWvqTLcbJ3zRvfzOcocEKYAD0OtWw3YGDvNOq2R4+9d3McxE+8bIlAQoMd59iDLrBHb5uERQAa+BbQTyfX9GfPDjYbwHyTEKIybNif3aTxciaalGYOpmRkADgivmu4quAxMH+30yTvYDVYLDRXNDCqrhWiWywKBgQCHo4M6As0XEyfOTmeZMoiW7Tk+lfI+KmBveGRqC8cfK7c1gkVbIZL20LDHgPbPmCJIP3t5o6ZvxEMfs+KFc5NJEoRYb2cN7kDREcmmi+kuW/XmgxgZEO0R+vNqs50Dz7mWeoN7B2VASWMQBE+saMFvXdtLs1TsSwmakiPyUV1bEQKBgG5bZZZuZnCzpNHChA0v+30RCWzeLpfRRqpT3CQM0l/nJqnLENHfsioG+3TRPOPEIJB+BSS+QmGJ8pej4JiNZ3kJbuwDzUgRPS3vHwGjB6fVoXDLnkND+RN75sUuzXoDERtzmQo/MzpobY8HobDQzpb70Pd6XRsAA9zxV9x96HshAoGBAKhunzyLB7qb8enqjpNROpgkSNDUL2Zlka98hP1NU2etx7aWJY7HlbEwojn0pxxIu3rNFJy32IbCiDdz6uFwuGlv+PXF58RRwHlTPNiUZa+5lDFqOfDyuBpuH64oGahI/+myCoHndTZ7M/Zcu+J2pG49Nk0006En/lrbZuvLG06W
 * Wrapped text:Run20QjVK8WQfmxtKhMNwJEg8L+fRg3HahRFeifgSnP0f0lpXhxLYUOpnvJkh4oKSjmgw0fo33ZeKzORVl7UrYUxDX4271AnlsO9520PF+WB1LzFs/p8a9mcHrCQfR+74IBF/h5EaCBxGybEWM2V/yMIsN8OTU8fHIpKx6VzFz6jNtZu4EG1txsXFDs7TFFLraY38q23ZRJLDoJvjZFDNroapL4p1pTkYIVirf4m/gXIr4ZDSKhgkJMhwKc05k5j6n1+wjcK1c/PUpdNIwvEbMd5vFJi1SofgfXVoLpfpJI8Dr4r5ZpgTL7+BUeuvTH/8EwcT8jeDEk/cYW33XiVnziMDjXsRVXWIEbQCB9MBbES/Gw33Pnt+i3noZagBLeo0JksGQGOPDOh1PLq7Z7NQ/DyHNcS2Hq7rFaFGUNGVkPs5eZ2bA4Nj1LZ1rEkI4W7qN4PkOrRQA4+IIexla+uhcj17H+ogt7DfJPP/Bf/HzYb+wurV1q84AdFpzB48ez7iFAKGNP7gTl4jJuergOsu/UsMT+f3WPtQTn0WcMrwfSmzLm+Gw63f8HLNo6kzVzal2LzEGlvPC0IZAPSNtugnhXuIDB+FB0wRGTIdbCas4Q=
 * Wrapped clau simètrica: pFhu4pD9wjgoCfQY+JJsLaB5GjW8mX0bnoiEPoE9Td3yAdqjRD02Vv1e5mqxp5yfvT+LcFm9CyIqu7Hnxq6lzpK+3y1bqKm7YwlNuVHUWioy9shIAUI2v4moW5UTiH0Yd91v0Xt+pdB5f2SOoUe7IsMhc7UeKepIgJLbeLVWAFFiYYixeUsT4cCm/c1H5wggZsL7ymK79E3Ve/GA8FhA6DFbZryNvMGluhp80rFa8k04m0wjyz2yiX8Y253xPOzGT1M7lPjiXs8S4S2NfZiNmDAPkdWTdxDiCdGZYodUjmunHr8A+9MocrY3gbwk5+MBpc5YaOpWBvlwKGmp47NNUQ==
 * 
 * Activitat 10 - RESULTAT
 * cNy2zYEO9HbVqfr2ueJxQo54rJrMZRXQdZORzPyqGq15HMsEAfabyGUvMTVM0Ac6vLRDBElVp47ANgI6Q5GbGdU1UEtWmNZ4Kr/fknx0QEUAc6d4HVeQ2krYQZTe3pMqKWcEQmNAtuA0G1EtrytDdpFpAsD/g1h/EGJQ+xlUYEKxOucax6hiD5TKTlWQdKOgGtOfKAPu23fnVm/igCsUtnfVlWC/qnR8Y0vUu6TpAM9aIK06rOIifGiIn8DAUKPaj9VAzKdRF+dwQLWM/EuVN3r1xEYtJWpplTppckKGlqChPmYuaclmBQx+3DucmuknMGN1MATuYNgCzVtNmpSVCA==
 *
 * Activitat 10 - RESULTAT CRYPTOLIB
 * GLgOv7xjamGfNzuFmc0NsZ5zrx8lSaRgcuQIDE4say0VzAe36/ZlgLgFYyA6tTsPmevII9k+QhQBeTuHjB4KgGi9ve1V4nsoWum/G4A8FsqnadMMrvkgXxfVSVmxXxs7cBemu6nvhxSGQWEIpew7kH5hI1I9gH8Sm8YcyvarRwi1NKjjJd7HhfNXFYnqb4cVVTWnpk23m5UxoWeAon+QdfGKAOAgOXSLYfAFG1KrOCsrx9TulCc4cU2MyV0DqypP9onf7z8NPVFieGU+B0A5P4cfbZwQx++VIk5qgjHyituqVlVDcqX4lH6oDcPNKXBhrlEKVNegW+Wy9G04ZJZjiw==
 *
 * @author pererdg
 */
public class Activitat11 {

	public static void main(String[] args) throws Exception {
		// Dades d'activitat 8
		String text = "Escriu un programa que generi les claus pública i privada amb una longitud de 2048 bits. Un cop creades, ha d’imprimir-les i comprovar-ne la longitud.\r\n"
			+ "Transforma les claus a base 64 i torna a imprimir-les.\r\n"
			+ "Amb aquestes claus, utilitzant el xifratge híbrid, ha de xifrar el text d’aquest enunciat (sense incloure el títol). El xifratge ha de ser amb AES i RSA i finalment escriure per pantalla tot el resultat del xifrat híbrid transformat a base 64.\r\n";
		String pub64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArqq/0Acd/e+ZGL3YMApN1YeZRjFcCN3IamxLhLlPL6m22SpSnu9Yz1SRY89DvK/U2kgQEccUrH6IgUKtPBnwRHpBBUkFKgW23eCkkbPW0ZHbxNAVXfNHkB8txcGn4BrpQ3R4YDx7UlA767N/ftBo5lnslUIVU/etI3TvblD6rnsApOb8Iz4YJk8ZzW27a3m/+MSlpFjY0lEaxI2kaWqmoZZpj0EqjehgePFVfgPb3XC8KwwdT++LnSCwmfrpX7ssfyccChgGRWIw86KWWsxhzBVY8cxHnfXJyiBRg0o+9OEjxiCtWuUK0Ip5JlLcRC3OUAnH6whqEGr8MgdmL0rlAQIDAQAB";
		String sign64 = "cNy2zYEO9HbVqfr2ueJxQo54rJrMZRXQdZORzPyqGq15HMsEAfabyGUvMTVM0Ac6vLRDBElVp47ANgI6Q5GbGdU1UEtWmNZ4Kr/fknx0QEUAc6d4HVeQ2krYQZTe3pMqKWcEQmNAtuA0G1EtrytDdpFpAsD/g1h/EGJQ+xlUYEKxOucax6hiD5TKTlWQdKOgGtOfKAPu23fnVm/igCsUtnfVlWC/qnR8Y0vUu6TpAM9aIK06rOIifGiIn8DAUKPaj9VAzKdRF+dwQLWM/EuVN3r1xEYtJWpplTppckKGlqChPmYuaclmBQx+3DucmuknMGN1MATuYNgCzVtNmpSVCA==";
		
		// Recuperar clau pública
		PublicKey pub = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(pub64)));
		
		// Signar i imprimir
		boolean valid = validarSignatura(pub, text, Base64.getDecoder().decode(sign64));
		System.out.println(valid);
		cryptoLib();
	}
		
	private static void cryptoLib() throws Exception {
		// Dades d'activitat 8
		String text = "Escriu un programa que generi les claus pública i privada amb una longitud de 2048 bits. Un cop creades, ha d’imprimir-les i comprovar-ne la longitud.\r\n"
			+ "Transforma les claus a base 64 i torna a imprimir-les.\r\n"
			+ "Amb aquestes claus, utilitzant el xifratge híbrid, ha de xifrar el text d’aquest enunciat (sense incloure el títol). El xifratge ha de ser amb AES i RSA i finalment escriure per pantalla tot el resultat del xifrat híbrid transformat a base 64.\r\n";
		String pub64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzGt5SimdRBlyZKri79UQk2MXVZ4sx9OXaMpM4+RGo5ghHK2LTPJY85yggQOr6b1OfaSCwEH3JpY8o0zkiQS5iJA92/IbNEf/vebMfxbHp24T5NV6irHBWjbZ1nvCMoTBrbcSHzXljmpMKSJbl2FZKWrghF7OLT4ZvIUvzlFlYiGDdXSl4Gw/WJKhiIxGun/cxIKTSVY7GqPeXao2sxvy/585wJKpHwRPPZMhYGJgq8OSD9AyNaOzFwW6XTdOgnu0xIr4u+2oSGsw3/uzOefT80s+yJBXIwfDHRpm2RcGlhUVd60w7u9uhuuFm5RdUkQQhxy5EsqKM0m2w9s8p7LewIDAQAB";
		String sign64 = "GLgOv7xjamGfNzuFmc0NsZ5zrx8lSaRgcuQIDE4say0VzAe36/ZlgLgFYyA6tTsPmevII9k+QhQBeTuHjB4KgGi9ve1V4nsoWum/G4A8FsqnadMMrvkgXxfVSVmxXxs7cBemu6nvhxSGQWEIpew7kH5hI1I9gH8Sm8YcyvarRwi1NKjjJd7HhfNXFYnqb4cVVTWnpk23m5UxoWeAon+QdfGKAOAgOXSLYfAFG1KrOCsrx9TulCc4cU2MyV0DqypP9onf7z8NPVFieGU+B0A5P4cfbZwQx++VIk5qgjHyituqVlVDcqX4lH6oDcPNKXBhrlEKVNegW+Wy9G04ZJZjiw==";
		
		// Recuperar clau pública
		PublicKey pub = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Crypto.decodeBase64(pub64)));
		
		// Signar i imprimir
		boolean valid = CryptoAsym.verifySignText(pub, text, Crypto.decodeBase64(sign64));
		System.out.println(valid);
	}
	
	/**
	 * Valida signatura de dades feta amb {@value #SIGN_INSTANCE}
	 * 
	 * @param pub Clau pública
	 * @param text Text signat
	 * @param signature Signatura
	 * @return True/false
	 * @throws Exception
	 */
	public static boolean validarSignatura(PublicKey pub, String text, byte[] signature) throws Exception {
		Signature signer = Signature.getInstance("SHA256withRSA");
		signer.initVerify(pub);
		signer.update(text.getBytes("UTF-8"));
		return signer.verify(signature);
	}
}
