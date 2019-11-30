package com.istring.utils;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class EncryptUtil {

	public static final String SIGN_TYPE_RSA = "RSA";

	public static final String SIGN_ALGORITHMS_SHA256RSA = "SHA256WithRSA";

	public static final String CHAR_ENCODE_UTF_8 = "UTF-8";

	/** RSA最大加密明文大小 */
	private static final int MAX_ENCRYPT_BLOCK = 245;

	/** RSA最大解密密文大小 */
	private static final int MAX_DECRYPT_BLOCK = 256;

	private static final String AES_ALG = "AES";

	/**
	 * AES算法
	 */
	private static final String AES_CBC_PKC_ALG = "AES/CBC/PKCS7Padding";

	private static final String AES_ECB_PKC_ALG = "AES/ECB/PKCS7Padding";

	private static final byte[] AES_IV = initIv(AES_CBC_PKC_ALG);

	static {
		// 如果是PKCS7Padding填充方式，则必须加上下面这行
		Security.addProvider(new BouncyCastleProvider());
	}

	public static void generateRSAKeyPairs() throws NoSuchAlgorithmException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);
		KeyPair keyPair = generator.genKeyPair();
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();
		System.out.println("publicKey = " + Base64.encodeBase64String(publicKey.getEncoded()));
		System.out.println("privateKey = " + Base64.encodeBase64String(privateKey.getEncoded()));
	}

	public static String sortBWalletSignContent(Map<String, String> sortedParams) {
		StringBuffer content = new StringBuffer();
		List<String> keys = new ArrayList<String>(sortedParams.keySet());
		Collections.sort(keys);
		for (int i = 0; i < keys.size(); i++) {
			String key = keys.get(i);
			String value = sortedParams.get(key);
			if (StringUtils.isNoneBlank(key, value)) {
				content.append(value);
			}
		}
		return content.toString();
	}

	public static String sortClearingSignContent(Map<String, String> sortedParams) {
		StringBuffer content = new StringBuffer();
		List<String> keys = new ArrayList<String>(sortedParams.keySet());
		Collections.sort(keys);
		int index = 0;
		for (int i = 0; i < keys.size(); i++) {
			String key = keys.get(i);
			String value = sortedParams.get(key);
			if (StringUtils.isNoneBlank(key, value)) {
				content.append((index == 0 ? "" : "&") + key + "=" + value);
				index++;
			}
		}
		return content.toString();
	}

	public static byte[] sha256(final String data) {
		return DigestUtils.sha256(data);
	}

	public static String sha256Hex(final String data) {
		return DigestUtils.sha256Hex(data);
	}

	public static String sha256Base64(final String data) {
		return encodeBase64String(DigestUtils.sha256(data));
	}

	public static String rsaSign(byte[] content, String privateKey) {

		try {

			PrivateKey priKey = getPrivateKeyFromPKCS8(SIGN_TYPE_RSA, new ByteArrayInputStream(privateKey.getBytes()));

			java.security.Signature signature = java.security.Signature.getInstance(SIGN_ALGORITHMS_SHA256RSA);

			signature.initSign(priKey);

			signature.update(content);

			byte[] signed = signature.sign();

			return encodeBase64String(signed);
		} catch (Exception e) {
			throw new RuntimeException("RSAcontent = " + content, e);
		}
	}

	public static String rsaSign(String content, String privateKey, String charset) {

		try {

			PrivateKey priKey = getPrivateKeyFromPKCS8(SIGN_TYPE_RSA, new ByteArrayInputStream(privateKey.getBytes()));

			java.security.Signature signature = java.security.Signature.getInstance(SIGN_ALGORITHMS_SHA256RSA);

			signature.initSign(priKey);

			if (StringUtils.isBlank(charset)) {
				signature.update(content.getBytes());
			} else {
				signature.update(content.getBytes(charset));
			}

			byte[] signed = signature.sign();

			return encodeBase64String(signed);
		} catch (Exception e) {
			throw new RuntimeException("RSAcontent = " + content + "; charset = " + charset, e);
		}
	}

	public static boolean rsaVerifySign(byte[] content, String sign, String publicKey) {
		try {

			PublicKey pubKey = getPublicKeyFromX509(SIGN_TYPE_RSA, new ByteArrayInputStream(publicKey.getBytes()));

			java.security.Signature signature = java.security.Signature.getInstance(SIGN_ALGORITHMS_SHA256RSA);

			signature.initVerify(pubKey);

			signature.update(content);

			return signature.verify(decodeBase64(sign.getBytes()));
		} catch (Exception e) {
			throw new RuntimeException("RSAcontent = " + content + ",sign=" + sign, e);
		}
	}

	public static boolean rsaVerifySign(String content, String sign, String publicKey, String charset) {
		try {

			PublicKey pubKey = getPublicKeyFromX509(SIGN_TYPE_RSA, new ByteArrayInputStream(publicKey.getBytes()));

			java.security.Signature signature = java.security.Signature.getInstance(SIGN_ALGORITHMS_SHA256RSA);

			signature.initVerify(pubKey);

			if (StringUtils.isBlank(charset)) {
				signature.update(content.getBytes());
			} else {
				signature.update(content.getBytes(charset));
			}

			return signature.verify(decodeBase64(sign.getBytes()));
		} catch (Exception e) {
			throw new RuntimeException("RSAcontent = " + content + ",sign=" + sign + ",charset = " + charset, e);
		}
	}

	public static String rsaEncrypt(String content, String publicKey, String charset) {
		ByteArrayOutputStream out = null;
		try {
			PublicKey pubKey = getPublicKeyFromX509(SIGN_TYPE_RSA, new ByteArrayInputStream(publicKey.getBytes()));
			Cipher cipher = Cipher.getInstance(SIGN_TYPE_RSA);
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			byte[] data = StringUtils.isBlank(charset) ? content.getBytes() : content.getBytes(charset);
			int inputLen = data.length;
			out = new ByteArrayOutputStream();
			int offSet = 0;
			byte[] cache;
			int i = 0;
			// 对数据分段加密
			while (inputLen - offSet > 0) {
				if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
					cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
				} else {
					cache = cipher.doFinal(data, offSet, inputLen - offSet);
				}
				out.write(cache, 0, cache.length);
				i++;
				offSet = i * MAX_ENCRYPT_BLOCK;
			}
			byte[] encryptedData = encodeBase64(out.toByteArray());

			return StringUtils.isBlank(charset) ? new String(encryptedData) : new String(encryptedData, charset);
		} catch (Exception e) {
			throw new RuntimeException("EncryptContent = " + content + ",charset = " + charset, e);
		} finally {
			try {
				if (out != null) {
					out.close();
				}
			} catch (IOException e) {
				throw new RuntimeException("EncryptContent = " + content + ",charset = " + charset, e);
			}
		}
	}

	public static byte[] rsaEncrypt(byte[] data, String publicKey) {
		ByteArrayOutputStream out = null;
		try {
			PublicKey pubKey = getPublicKeyFromX509(SIGN_TYPE_RSA, new ByteArrayInputStream(publicKey.getBytes()));
			Cipher cipher = Cipher.getInstance(SIGN_TYPE_RSA);
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			int inputLen = data.length;
			out = new ByteArrayOutputStream();
			int offSet = 0;
			byte[] cache;
			int i = 0;
			// 对数据分段加密
			while (inputLen - offSet > 0) {
				if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
					cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
				} else {
					cache = cipher.doFinal(data, offSet, inputLen - offSet);
				}
				out.write(cache, 0, cache.length);
				i++;
				offSet = i * MAX_ENCRYPT_BLOCK;
			}
			byte[] encryptedData = out.toByteArray();

			return encryptedData;
		} catch (Exception e) {
			throw new RuntimeException("EncryptContent = " + data, e);
		} finally {
			try {
				if (out != null) {
					out.close();
				}
			} catch (IOException e) {
				throw new RuntimeException("EncryptContent = " + data, e);
			}
		}
	}

	public static String rsaEncryptWithPrivateKey(String content, String privateKey, String charset) {
		ByteArrayOutputStream out = null;
		try {
			PrivateKey priKey = getPrivateKeyFromPKCS8(SIGN_TYPE_RSA, new ByteArrayInputStream(privateKey.getBytes()));
			Cipher cipher = Cipher.getInstance(SIGN_TYPE_RSA);
			cipher.init(Cipher.ENCRYPT_MODE, priKey);
			byte[] data = StringUtils.isBlank(charset) ? content.getBytes() : content.getBytes(charset);
			int inputLen = data.length;
			out = new ByteArrayOutputStream();
			int offSet = 0;
			byte[] cache;
			int i = 0;
			// 对数据分段加密
			while (inputLen - offSet > 0) {
				if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
					cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
				} else {
					cache = cipher.doFinal(data, offSet, inputLen - offSet);
				}
				out.write(cache, 0, cache.length);
				i++;
				offSet = i * MAX_ENCRYPT_BLOCK;
			}
			byte[] encryptedData = encodeBase64(out.toByteArray());

			return StringUtils.isBlank(charset) ? new String(encryptedData) : new String(encryptedData, charset);
		} catch (Exception e) {
			throw new RuntimeException("EncryptContent = " + content + ",charset = " + charset, e);
		} finally {
			try {
				if (out != null) {
					out.close();
				}
			} catch (IOException e) {
				throw new RuntimeException("EncryptContent = " + content + ",charset = " + charset, e);
			}
		}
	}

	public static byte[] rsaEncryptWithPrivateKey(byte[] content, String privateKey) {
		ByteArrayOutputStream out = null;
		try {
			PrivateKey priKey = getPrivateKeyFromPKCS8(SIGN_TYPE_RSA, new ByteArrayInputStream(privateKey.getBytes()));
			Cipher cipher = Cipher.getInstance(SIGN_TYPE_RSA);
			cipher.init(Cipher.ENCRYPT_MODE, priKey);
			int inputLen = content.length;
			out = new ByteArrayOutputStream();
			int offSet = 0;
			byte[] cache;
			int i = 0;
			// 对数据分段加密
			while (inputLen - offSet > 0) {
				if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
					cache = cipher.doFinal(content, offSet, MAX_ENCRYPT_BLOCK);
				} else {
					cache = cipher.doFinal(content, offSet, inputLen - offSet);
				}
				out.write(cache, 0, cache.length);
				i++;
				offSet = i * MAX_ENCRYPT_BLOCK;
			}
			byte[] encryptedData = out.toByteArray();

			return encryptedData;
		} catch (Exception e) {
			throw new RuntimeException("EncryptContent = " + content, e);
		} finally {
			try {
				if (out != null) {
					out.close();
				}
			} catch (IOException e) {
				throw new RuntimeException("EncryptContent = " + content, e);
			}
		}
	}

	public static String rsaDecrypt(String content, String privateKey, String charset) {

		ByteArrayOutputStream out = null;
		try {
			PrivateKey priKey = getPrivateKeyFromPKCS8(SIGN_TYPE_RSA, new ByteArrayInputStream(privateKey.getBytes()));
			Cipher cipher = Cipher.getInstance(SIGN_TYPE_RSA);
			cipher.init(Cipher.DECRYPT_MODE, priKey);
			byte[] encryptedData = StringUtils.isEmpty(charset) ? decodeBase64(content.getBytes())
					: decodeBase64(content.getBytes(charset));
			int inputLen = encryptedData.length;
			out = new ByteArrayOutputStream();
			int offSet = 0;
			byte[] cache;
			int i = 0;
			// 对数据分段解密
			while (inputLen - offSet > 0) {
				if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
					cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
				} else {
					cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
				}
				out.write(cache, 0, cache.length);
				i++;
				offSet = i * MAX_DECRYPT_BLOCK;
			}
			byte[] decryptedData = out.toByteArray();

			return StringUtils.isEmpty(charset) ? new String(decryptedData) : new String(decryptedData, charset);
		} catch (Exception e) {
			throw new RuntimeException("EncodeContent = " + content + ",charset = " + charset, e);
		} finally {
			try {
				if (out != null) {
					out.close();
				}
			} catch (IOException e) {
				throw new RuntimeException("EncryptContent = " + content + ",charset = " + charset, e);
			}
		}
	}

	public static byte[] rsaDecrypt(byte[] content, String privateKey) {

		ByteArrayOutputStream out = null;
		try {
			PrivateKey priKey = getPrivateKeyFromPKCS8(SIGN_TYPE_RSA, new ByteArrayInputStream(privateKey.getBytes()));
			Cipher cipher = Cipher.getInstance(SIGN_TYPE_RSA);
			cipher.init(Cipher.DECRYPT_MODE, priKey);
			int inputLen = content.length;
			out = new ByteArrayOutputStream();
			int offSet = 0;
			byte[] cache;
			int i = 0;
			// 对数据分段解密
			while (inputLen - offSet > 0) {
				if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
					cache = cipher.doFinal(content, offSet, MAX_DECRYPT_BLOCK);
				} else {
					cache = cipher.doFinal(content, offSet, inputLen - offSet);
				}
				out.write(cache, 0, cache.length);
				i++;
				offSet = i * MAX_DECRYPT_BLOCK;
			}
			byte[] decryptedData = out.toByteArray();

			return decryptedData;
		} catch (Exception e) {
			throw new RuntimeException("EncodeContent = " + content, e);
		} finally {
			try {
				if (out != null) {
					out.close();
				}
			} catch (IOException e) {
				throw new RuntimeException("EncryptContent = " + content, e);
			}
		}
	}

	public static String rsaDecryptWithPublicKey(String content, String publicKey, String charset) {

		ByteArrayOutputStream out = null;
		try {
			PublicKey pubKey = getPublicKeyFromX509(SIGN_TYPE_RSA, new ByteArrayInputStream(publicKey.getBytes()));
			Cipher cipher = Cipher.getInstance(SIGN_TYPE_RSA);
			cipher.init(Cipher.DECRYPT_MODE, pubKey);
			byte[] encryptedData = StringUtils.isEmpty(charset) ? decodeBase64(content.getBytes())
					: decodeBase64(content.getBytes(charset));
			int inputLen = encryptedData.length;
			out = new ByteArrayOutputStream();
			int offSet = 0;
			byte[] cache;
			int i = 0;
			// 对数据分段解密
			while (inputLen - offSet > 0) {
				if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
					cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
				} else {
					cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
				}
				out.write(cache, 0, cache.length);
				i++;
				offSet = i * MAX_DECRYPT_BLOCK;
			}
			byte[] decryptedData = out.toByteArray();

			return StringUtils.isEmpty(charset) ? new String(decryptedData) : new String(decryptedData, charset);
		} catch (Exception e) {
			throw new RuntimeException("EncodeContent = " + content + ",charset = " + charset, e);
		} finally {
			try {
				if (out != null) {
					out.close();
				}
			} catch (IOException e) {
				throw new RuntimeException("EncryptContent = " + content + ",charset = " + charset, e);
			}
		}
	}

	public static byte[] rsaDecryptWithPublicKey(byte[] content, String publicKey) {

		ByteArrayOutputStream out = null;
		try {
			PublicKey pubKey = getPublicKeyFromX509(SIGN_TYPE_RSA, new ByteArrayInputStream(publicKey.getBytes()));
			Cipher cipher = Cipher.getInstance(SIGN_TYPE_RSA);
			cipher.init(Cipher.DECRYPT_MODE, pubKey);
			int inputLen = content.length;
			out = new ByteArrayOutputStream();
			int offSet = 0;
			byte[] cache;
			int i = 0;
			// 对数据分段解密
			while (inputLen - offSet > 0) {
				if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
					cache = cipher.doFinal(content, offSet, MAX_DECRYPT_BLOCK);
				} else {
					cache = cipher.doFinal(content, offSet, inputLen - offSet);
				}
				out.write(cache, 0, cache.length);
				i++;
				offSet = i * MAX_DECRYPT_BLOCK;
			}
			byte[] decryptedData = out.toByteArray();

			return decryptedData;
		} catch (Exception e) {
			throw new RuntimeException("EncodeContent = " + content, e);
		} finally {
			try {
				if (out != null) {
					out.close();
				}
			} catch (IOException e) {
				throw new RuntimeException("EncryptContent = " + content, e);
			}
		}
	}

	public static PublicKey getPublicKeyFromX509(String algorithm, InputStream ins) throws Exception {

		KeyFactory keyFactory = KeyFactory.getInstance(algorithm);

		byte[] encodedKey = IOUtils.toByteArray(ins);

		encodedKey = decodeBase64(encodedKey);

		return keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
	}

	public static PrivateKey getPrivateKeyFromPKCS8(String algorithm, InputStream ins) throws Exception {

		KeyFactory keyFactory = KeyFactory.getInstance(algorithm);

		byte[] encodedKey = IOUtils.toByteArray(ins);

		encodedKey = decodeBase64(encodedKey);

		return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encodedKey));
	}

	public static byte[] encodeBase64(final byte[] binaryData) {
		return Base64.encodeBase64(binaryData);
	}

	public static String encodeBase64String(final byte[] binaryData) {
		return Base64.encodeBase64String(binaryData);
	}

	public static byte[] decodeBase64(final byte[] base64Data) {
		return Base64.decodeBase64(base64Data);
	}

	public static byte[] decodeBase64(final String data) {
		return Base64.decodeBase64(data);
	}

	public static String generateAESKey() {
		try {
			KeyGenerator kg = KeyGenerator.getInstance(AES_ALG);
			kg.init(128);
			SecretKey secretKey = kg.generateKey();
			return encodeBase64String(secretKey.getEncoded());
		} catch (Exception e) {
			throw new RuntimeException("生成AES加密key失败", e);
		}
	}

	public static byte[] generateAESKey(int keysize) {
		try {
			KeyGenerator kg = KeyGenerator.getInstance(AES_ALG);
			kg.init(keysize);
			SecretKey secretKey = kg.generateKey();
			return secretKey.getEncoded();
		} catch (Exception e) {
			throw new RuntimeException("生成AES加密key失败", e);
		}
	}

	public static String aesEncryptByECBPKCS7Padding(String content, String aesKey) {
		try {
			Cipher cipher = Cipher.getInstance(AES_ECB_PKC_ALG, "BC");
			SecretKeySpec secretKeySpec = new SecretKeySpec(aesKey.getBytes(CHAR_ENCODE_UTF_8), AES_ALG);
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
			byte[] encryptBytes = cipher.doFinal(content.getBytes(CHAR_ENCODE_UTF_8));
			return encodeBase64String(encryptBytes);
		} catch (Exception e) {
			throw new RuntimeException("AES加密失败：Aescontent = " + content + "; aesKey = " + aesKey, e);
		}
	}

	/**
	 * AES加密
	 * 
	 * @param content
	 * @param aesKey
	 * @return
	 */
	public static String aesEncryptByCBCPKCS7Padding(String content, String aesKey) {
		try {
			Cipher cipher = Cipher.getInstance(AES_CBC_PKC_ALG, "BC");
			SecretKeySpec secretKeySpec = new SecretKeySpec(aesKey.getBytes(CHAR_ENCODE_UTF_8), AES_ALG);
			IvParameterSpec iv = new IvParameterSpec(AES_IV);
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);
			byte[] encryptBytes = cipher.doFinal(content.getBytes(CHAR_ENCODE_UTF_8));
			return encodeBase64String(encryptBytes);
		} catch (Exception e) {
			throw new RuntimeException("AES加密失败：Aescontent = " + content + "; aesKey = " + aesKey, e);
		}
	}

	/**
	 * AES加密
	 * 
	 * @param content
	 * @param aesKey
	 * @return
	 */
	public static String aesEncryptByCBCPKCS7Padding(String content, byte[] aesKey, byte[] iv) {
		try {
			Cipher cipher = Cipher.getInstance(AES_CBC_PKC_ALG, "BC");
			SecretKeySpec secretKeySpec = new SecretKeySpec(aesKey, AES_ALG);
			IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
			byte[] encryptBytes = cipher.doFinal(content.getBytes(CHAR_ENCODE_UTF_8));
			return encodeBase64String(encryptBytes);
		} catch (Exception e) {
			throw new RuntimeException("AES加密失败：Aescontent = " + content + "; aesKey = " + aesKey, e);
		}
	}

	public static String aesDecryptByECBPKCS7Padding(String content, String aesKey) {
		try {
			Cipher cipher = Cipher.getInstance(AES_ECB_PKC_ALG, "BC");
			SecretKeySpec secretKeySpec = new SecretKeySpec(aesKey.getBytes(CHAR_ENCODE_UTF_8), AES_ALG);
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
			byte[] decryptBytes = cipher.doFinal(decodeBase64(content));
			return new String(decryptBytes, CHAR_ENCODE_UTF_8);
		} catch (Exception e) {
			throw new RuntimeException("AES解密失败：Aescontent = " + content + "; charset = " + CHAR_ENCODE_UTF_8, e);
		}
	}

	/**
	 * AES解密
	 * 
	 * @param content
	 * @param aesKey
	 * @return
	 */
	public static String aesDecryptByCBCPKCS7Padding(String content, String aesKey) {
		try {
			Cipher cipher = Cipher.getInstance(AES_CBC_PKC_ALG, "BC");
			SecretKeySpec secretKeySpec = new SecretKeySpec(aesKey.getBytes(CHAR_ENCODE_UTF_8), AES_ALG);
			IvParameterSpec iv = new IvParameterSpec(AES_IV);
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);
			byte[] decryptBytes = cipher.doFinal(decodeBase64(content));
			return new String(decryptBytes, CHAR_ENCODE_UTF_8);
		} catch (Exception e) {
			throw new RuntimeException("AES解密失败：Aescontent = " + content + "; charset = " + CHAR_ENCODE_UTF_8, e);
		}
	}

	/**
	 * AES解密
	 * 
	 * @param content
	 * @param aesKey
	 * @return
	 */
	public static String aesDecryptByCBCPKCS7Padding(String content, byte[] aesKey, byte[] iv) {
		try {
			Cipher cipher = Cipher.getInstance(AES_CBC_PKC_ALG, "BC");
			SecretKeySpec secretKeySpec = new SecretKeySpec(aesKey, AES_ALG);
			IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
			byte[] decryptBytes = cipher.doFinal(decodeBase64(content));
			return new String(decryptBytes, CHAR_ENCODE_UTF_8);
		} catch (Exception e) {
			throw new RuntimeException("AES解密失败：Aescontent = " + content + "; charset = " + CHAR_ENCODE_UTF_8, e);
		}
	}

	/**
	 * 初始向量的方法, 全部为0. 这里的写法适合于其它算法,针对AES算法的话,IV值一定是128位的(16字节).
	 *
	 * @param fullAlg
	 * @return
	 */
	private static byte[] initIv(String fullAlg) {
		try {
			// 如果是PKCS7Padding填充方式，则必须加上下面这行
			Security.addProvider(new BouncyCastleProvider());
			Cipher cipher = Cipher.getInstance(fullAlg);
			int blockSize = cipher.getBlockSize();
			byte[] iv = new byte[blockSize];
			for (int i = 0; i < blockSize; ++i) {
				iv[i] = 0;
			}
			return iv;
		} catch (Exception e) {
			int blockSize = 16;
			byte[] iv = new byte[blockSize];
			for (int i = 0; i < blockSize; ++i) {
				iv[i] = 0;
			}
			return iv;
		}
	}

}
