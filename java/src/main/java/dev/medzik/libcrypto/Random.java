package dev.medzik.libcrypto;

import java.security.SecureRandom;

public final class Random {
    /** Generate a random byte array. */
    public static byte[] randBytes(int length) {
        SecureRandom rd = new SecureRandom();
        byte[] salt = new byte[length];
        rd.nextBytes(salt);
        return salt;
    }
}
