package dev.medzik.libcrypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public final class AesTests {
    @Test
    public void testCBCEncryptAndDecrypt() throws AesException {
        byte[] secretKey = Hex.decode("82fd4cefd6efde36171900b469bae4e06863cb70f80b4e216e44eeb0cf30460b");

        String input = "Hello World!";
        String cipherText =  Aes.encrypt(Aes.CBC, secretKey, input.getBytes());
        byte[] clearBytes = Aes.decrypt(Aes.CBC, secretKey, cipherText);

        assertEquals(input, new String(clearBytes));
    }

    @Test
    public void testCBCDecrypt() throws AesException {
        byte[] secretKey = Hex.decode("82fd4cefd6efde36171900b469bae4e06863cb70f80b4e216e44eeb0cf30460b");

        String cipherText = "ae77d812f4494a766a94b5dff8e7aa3c8408544b9fd30cd13b886cc5dd1b190e";
        byte[] clearBytes = Aes.decrypt(Aes.CBC, secretKey, cipherText);

        assertEquals("hello world", new String(clearBytes));
    }

    @Test
    public void testGCMEncryptAndDecrypt() throws AesException {
        byte[] secretKey = Hex.decode("82fd4cefd6efde36171900b469bae4e06863cb70f80b4e216e44eeb0cf30460b");

        String input = "Hello World!";
        String cipherText =  Aes.encrypt(Aes.GCM, secretKey, input.getBytes());
        byte[] clearBytes = Aes.decrypt(Aes.GCM, secretKey, cipherText);

        assertEquals(input, new String(clearBytes));
    }

    @Test
    void testGCMDecrypt() throws AesException {
        byte[] secretKey = Hex.decode("82fd4cefd6efde36171900b469bae4e06863cb70f80b4e216e44eeb0cf30460b");

        String cipherText = "0996c65a72a60e748415dc6d32da1d4dcb65f41c71d4bec9554424218839b5d4b9d9195e5eea9d";
        byte[] clearBytes = Aes.decrypt(Aes.GCM, secretKey, cipherText);

        assertEquals("hello world", new String(clearBytes));
    }
}
