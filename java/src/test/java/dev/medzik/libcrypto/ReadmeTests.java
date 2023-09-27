package dev.medzik.libcrypto;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidKeyException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ReadmeTests {
    @Test
    public void testAesGcmEncryptDecryption() throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, DecoderException {
        String clearText = "hello world";
        // Key used for encryption (for example, argon2 hash in hex string)
        String secretKey = "82fd4cefd6efde36171900b469bae4e06863cb70f80b4e216e44eeb0cf30460b";

        // Encrypt using AES-GCM (AES-CBC is also available)
        String cipherText = Aes.encrypt(Aes.GCM, Hex.decodeHex(secretKey), clearText.getBytes());

        // Decrypt cipher text
        byte[] decryptedBytes = Aes.decrypt(Aes.GCM, Hex.decodeHex(secretKey), cipherText);

        assertEquals(clearText, new String(decryptedBytes));
    }

    @Test
    public void testArgon2Hash() {
        // Create instance for Argon2id hasher (i and d are also possible)
        Argon2 argon2 = new Argon2.Builder()
                .setHashLength(32)
                .setIterations(4)
                .setMemory(65536)
                .setParallelism(4)
                .setType(Argon2Type.ID)
                .setVersion(Argon2.ARGON2_VERSION_13)
                .build();

        // Compute a hash of password with random 16-byte salt
        Argon2Hash hash = argon2.hash("secret password", Random.randBytes(16));

        // Secret Key used for AES encryption
        String secretKey = Hex.encodeHexString(hash.getHash());

        assertTrue(Argon2.verify("secret password", hash.toString()));
    }

    @Test
    public void testX25519ExchangeKeys() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, DecoderException {
        // Generate private key for Bob
        byte[] bobPrivateKey = X25519.generatePrivateKey();
        byte[] bobPublicKey = X25519.publicFromPrivate(bobPrivateKey);

        // Generate private and public keys for Alice
        byte[] alicePrivateKey = X25519.generatePrivateKey();
        byte[] alicePublicKey = X25519.publicFromPrivate(alicePrivateKey);

        // Bob sends "hello world" to Alice

        // Compute shared secret between Bob and Alice
        byte[] sharedSecret_bob = X25519.computeSharedSecret(bobPrivateKey, alicePublicKey);

        // Encrypt message
        String message = "hello world";
        String encryptedMessage = Aes.encrypt(Aes.GCM, sharedSecret_bob, message.getBytes());

        // Alice decrypts a message from Bob

        // The same as `sharedSecret_bob`
        byte[] sharedSecret_alice = X25519.computeSharedSecret(alicePrivateKey, bobPublicKey);

        // Decrypt message
        byte[] decryptedMessageBytes = Aes.decrypt(Aes.GCM, sharedSecret_alice, encryptedMessage);
        String decryptedMessage = new String(decryptedMessageBytes);

        assertEquals(message, decryptedMessage);
    }
}
