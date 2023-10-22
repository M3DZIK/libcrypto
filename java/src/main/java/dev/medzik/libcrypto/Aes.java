package dev.medzik.libcrypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.AlgorithmParameterSpec;

public final class Aes {
    private static final String ALGORITHM = "AES";

    public static final AesType GCM = AesType.GCM;
    public static final AesType CBC = AesType.CBC;

    /**
     * Encrypts the given clear bytes using AES with the given key and random IV.
     *
     * @param type AES type to use
     * @param key secret key to use for encryption
     * @param clearBytes clear bytes to encrypt (UTF-8)
     * @return Encrypted cipher (hex encoded)
     * @throws AesException if encryption fails
     */
    public static String encrypt(AesType type, byte[] key, byte[] clearBytes) throws AesException {
        // generate random IV
        byte[] iv = Random.randBytes(type.getIvLength());

        SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);
        AlgorithmParameterSpec parameterSpec = getParameterSpec(type, iv);

        // initialize cipher
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(type.getMode());
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        } catch (Exception e) {
            throw new AesException("Failed to init cipher", e);
        }

        // encrypt
        byte[] cipherBytes;
        try {
            cipherBytes = cipher.doFinal(clearBytes);
        } catch (Exception e) {
            throw new AesException("Failed to finalize encryption", e);
        }

        // return IV + cipher text as hex string
        return Hex.encode(iv) + Hex.encode(cipherBytes);
    }

    /**
     * Decrypts the given cipher text using AES with the given key.
     *
     * @param type AES type to use
     * @param key secret key to use for decryption
     * @param cipherText cipher text to decrypt (hex encoded)
     * @return Decrypted bytes
     * @throws AesException if decryption fails
     */
    public static byte[] decrypt(AesType type, byte[] key, String cipherText) throws AesException {
        // get IV length in hex string
        int ivLength = type.getIvLength() * 2;

        // extract IV and Cipher Text from hex string
        byte[] iv = Hex.decode(cipherText.substring(0, ivLength));
        byte[] cipherBytes = Hex.decode(cipherText.substring(ivLength));

        SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);
        AlgorithmParameterSpec parameterSpec = getParameterSpec(type, iv);

        // initialize cipher
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(type.getMode());
            cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
        } catch (Exception e) {
            throw new AesException("Failed to init cipher", e);
        }

        // decrypt
        try {
            return cipher.doFinal(cipherBytes);
        } catch (Exception e) {
            throw new AesException("Failed to finalize decryption", e);
        }
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
