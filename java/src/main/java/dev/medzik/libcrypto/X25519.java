// https://github.com/tink-crypto/tink-java/blob/3a0087c1aca0e4bc148d26e7ca0a7bfaa42e46a9/src/main/java/com/google/crypto/tink/subtle/X25519.java#L57

package dev.medzik.libcrypto;

import dev.medzik.libcrypto.internal.Curve25519;
import dev.medzik.libcrypto.internal.Field25519;

import java.security.InvalidKeyException;
import java.util.Arrays;

public final class X25519 {
    /**
     * Generates a 32-byte private key for Curve25519.
     * @return a 32-byte private key
     */
    public static byte[] generatePrivateKey() {
        byte[] privateKey = Random.randBytes(Field25519.FIELD_LEN);

        privateKey[0] |= 7;
        privateKey[31] &= 63;
        privateKey[31] |= 128;

        return privateKey;
    }

    /**
     * Computes a 32-byte shared secret between two users.
     * @param ourPrivate 32-byte private key
     * @param theirPublic 32-byte public key
     * @return 32-byte shared secret
     * @throws InvalidKeyException when {@code ourPrivate} is not 32-byte or {@code theirPublic} is invalid.
     */
    public static byte[] computeSharedSecret(byte[] ourPrivate, byte[] theirPublic)
            throws InvalidKeyException {
        if (ourPrivate.length != Field25519.FIELD_LEN) {
            throw new InvalidKeyException("Private key must have 32 bytes.");
        }
        long[] x = new long[Field25519.LIMB_CNT + 1];

        byte[] e = Arrays.copyOf(ourPrivate, Field25519.FIELD_LEN);
        e[0] &= 248;
        e[31] &= 127;
        e[31] |= 64;

        Curve25519.curveMult(x, e, theirPublic);
        return Field25519.contract(x);
    }

    /**
     * Recovers public key from a private key
     * @param privateKey 32-byte private key
     * @return 32-byte public key
     * @throws InvalidKeyException when the {@code privateKey} is not 32 bytes.
     */
    public static byte[] publicFromPrivate(byte[] privateKey) throws InvalidKeyException {
        if (privateKey.length != Field25519.FIELD_LEN) {
            throw new InvalidKeyException("Private key must have 32 bytes.");
        }
        byte[] base = new byte[Field25519.FIELD_LEN];
        base[0] = 9;
        return computeSharedSecret(privateKey, base);
    }
}
