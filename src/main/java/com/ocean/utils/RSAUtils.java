package com.ocean.utils;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @author huhaiyang
 * @date 2022/9/26
 */
public class RSAUtils {
    private static final String ALGORITHM = "RSA";
    private static final int KEY_SIZE = 2048;

    /**
     * 生成公私钥对
     *
     * @return
     * @throws Exception
     */
    public static KeyPair generateKeyPair() throws Exception {
        //获取指定算法的生成器
        KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM);
        generator.initialize(KEY_SIZE);
        return generator.generateKeyPair();
    }

    /**
     * 将公私钥以Base64存入文件中
     *
     * @param key
     * @param file
     * @throws IOException
     */
    public static void saveKeyWithBase64(Key key, File file) throws IOException {
        byte[] bytes = key.getEncoded();
        String base64 = new BASE64Encoder().encode(bytes);
        IOUtils.writeToFile(base64, file);
    }

    /**
     * 获取公钥对象
     *
     * @param publicKeyBase64
     * @return
     */
    public static PublicKey getPublicKey(String publicKeyBase64) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] publicKeyBytes = new BASE64Decoder().decodeBuffer(publicKeyBase64);
        X509EncodedKeySpec publicKey = new X509EncodedKeySpec(publicKeyBytes);
        return KeyFactory.getInstance(ALGORITHM).generatePublic(publicKey);
    }

    /**
     * 获取私钥对象
     *
     * @param privateKeyBase64
     * @return
     */
    public static PrivateKey getPrivateKey(String privateKeyBase64) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] privateKeyBytes = new BASE64Decoder().decodeBuffer(privateKeyBase64);
        PKCS8EncodedKeySpec privateKey = new PKCS8EncodedKeySpec(privateKeyBytes);
        return KeyFactory.getInstance(ALGORITHM).generatePrivate(privateKey);
    }

    /**
     * 公钥加密
     *
     * @param plainData
     * @param publicKey
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static byte[] encrypt(byte[] plainData, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        //获取密码器
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plainData);
    }

    /**
     * 私钥解密
     *
     * @param cipherData
     * @param privateKey
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static byte[] decrypt(byte[] cipherData, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        //获取密码器
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE,privateKey);
        return cipher.doFinal(cipherData);
    }

}
