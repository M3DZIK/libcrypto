package dev.medzik.libcrypto;

import java.security.SecureRandom;

public final class Random {
    /**
     * Generate a random byte array.
     * @param size length of salt slice in bytes
     */
    public static byte[] randBytes(int size) {
        SecureRandom rd = new SecureRandom();
        byte[] salt = new byte[size];
        rd.nextBytes(salt);
        return salt;
    }
}
