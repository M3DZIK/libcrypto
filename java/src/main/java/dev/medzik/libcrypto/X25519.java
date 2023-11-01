package dev.medzik.libcrypto;

import java.security.InvalidKeyException;
import java.security.SecureRandom;

import static org.bouncycastle.math.ec.rfc7748.X25519.POINT_SIZE;
import static org.bouncycastle.math.ec.rfc7748.X25519.calculateAgreement;

public final class X25519 {
    /** Generates a 32-byte private key for Curve25519. */
    public static byte[] generatePrivateKey() {
        byte[] privateKey = new byte[POINT_SIZE];
        org.bouncycastle.math.ec.rfc7748.X25519.generatePrivateKey(new SecureRandom(), privateKey);
        return privateKey;
    }

    /**
     * Computes a 32-byte shared secret between two users.
     * @param ourPrivate 32-byte private key
     * @param theirPublic 32-byte public key
     * @return 32-byte shared secret
     * @throws InvalidKeyException when {@code ourPrivate} is not 32-byte or {@code theirPublic} is invalid.
     */
    public static byte[] computeSharedSecret(byte[] ourPrivate, byte[] theirPublic) throws InvalidKeyException {
        if (ourPrivate.length != POINT_SIZE) {
            throw new InvalidKeyException("Private key must have 32 bytes.");
        }

        if (theirPublic.length != POINT_SIZE) {
            throw new InvalidKeyException("Public key must have 32 bytes.");
        }

        byte[] encoded = new byte[POINT_SIZE];
        calculateAgreement(ourPrivate, 0, theirPublic, 0, encoded, 0);
        return encoded;
    }

    /**
     * Recovers public key from a private key
     * @param privateKey 32-byte private key
     * @return 32-byte public key
     * @throws InvalidKeyException when the {@code privateKey} is not 32 bytes.
     */
    public static byte[] publicFromPrivate(byte[] privateKey) throws InvalidKeyException {
        if (privateKey.length != POINT_SIZE) {
            throw new InvalidKeyException("Private key must have 32 bytes.");
        }

        byte[] publicKey = new byte[POINT_SIZE];
        org.bouncycastle.math.ec.rfc7748.X25519.generatePublicKey(privateKey, 0, publicKey, 0);
        return publicKey;
    }
}
