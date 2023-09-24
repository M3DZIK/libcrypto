package dev.medzik.libcrypto;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

public class Aes {
    private static final String ALGORITHM = "AES";

    public static final AesType GCM = AesType.GCM;
    public static final AesType CBC = AesType.CBC;

    /**
     * Encrypts the given clear bytes using AES with the given key and random IV.
     * @param type AES type to use
     * @param key secret key to use for encryption
     * @param clearBytes clear bytes to encrypt (UTF-8)
     */
    public static String encrypt(AesType type, byte[] key, byte[] clearBytes) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        // generate random IV
        byte[] iv = Random.randBytes(type.getIvLength());

        SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);
        AlgorithmParameterSpec parameterSpec = getParameterSpec(type, iv);

        // initialize cipher
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(type.getMode());
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        } catch (InvalidAlgorithmParameterException |
                 NoSuchPaddingException |
                 NoSuchAlgorithmException e) {
            // never happen
            throw new RuntimeException(e);
        }

        // encrypt
        byte[] cipherBytes = cipher.doFinal(clearBytes);

        // return IV + cipher text as hex string
        return Hex.encodeHexString(iv) + Hex.encodeHexString(cipherBytes);
    }

    /**
     * Decrypts the given cipher text using AES with the given key.
     * @param type AES type to use
     * @param key secret key to use for decryption
     * @param cipherText cipher text to decrypt (hex encoded)
     * @return Decrypted bytes
     */
    public static byte[] decrypt(AesType type, byte[] key, String cipherText) throws DecoderException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        // get IV length in hex string
        int ivLength = type.getIvLength() * 2;

        // extract IV and Cipher Text from hex string
        byte[] iv = Hex.decodeHex(cipherText.substring(0, ivLength));
        byte[] cipherBytes = Hex.decodeHex(cipherText.substring(ivLength));

        SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);
        AlgorithmParameterSpec parameterSpec = getParameterSpec(type, iv);

        // initialize cipher
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(type.getMode());
            cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
        } catch (InvalidAlgorithmParameterException |
                 NoSuchPaddingException |
                 NoSuchAlgorithmException e) {
            // never happen
            throw new RuntimeException(e);
        }

        // decrypt
        return cipher.doFinal(cipherBytes);
    }

    private static AlgorithmParameterSpec getParameterSpec(AesType type, byte[] iv) {
        switch (type) {
            case CBC:
                return new IvParameterSpec(iv);
            case GCM:
                return new GCMParameterSpec(128, iv);
        }

        // never happen
        return null;
    }

    public enum AesType {
        CBC("AES/CBC/PKCS5Padding", 16),
        GCM("AES/GCM/NoPadding", 12);

        private final String mode;
        private final int ivLength;

        AesType(String mode, int ivLength) {
            this.mode = mode;
            this.ivLength = ivLength;
        }

        private String getMode() {
            return mode;
        }

        private int getIvLength() {
            return ivLength;
        }
    }
}
