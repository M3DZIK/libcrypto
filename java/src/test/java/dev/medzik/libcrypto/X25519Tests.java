package dev.medzik.libcrypto;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;

import static org.junit.jupiter.api.Assertions.assertEquals;

public final class X25519Tests {
    @Test
    public void testComputeSharedSecret() throws DecoderException, InvalidKeyException {
        byte[] privateKey = Hex.decodeHex("3845bead1f44408ee436c742291f1362489eeaaa9daebd480b1c3e4bc528cb48");
        byte[] publicKey = Hex.decodeHex("9d49b72cf49defc6748c67ab274a1c2f096362ef3b2d691793686589760b4e25");

        byte[] sharedSecret = X25519.computeSharedSecret(privateKey, publicKey);

        assertEquals(Hex.encodeHexString(sharedSecret), "2bebf3c397ab3c79db9aeeb2c1523ab4a32bd1ae335a19cd47e35983a5184d09");
    }

    @Test
    public void testPublicKeyFromPrivate() throws DecoderException, InvalidKeyException {
        byte[] privateKey = Hex.decodeHex("3845bead1f44408ee436c742291f1362489eeaaa9daebd480b1c3e4bc528cb48");

        byte[] publicKey = X25519.publicFromPrivate(privateKey);

        assertEquals(Hex.encodeHexString(publicKey), "9d49b72cf49defc6748c67ab274a1c2f096362ef3b2d691793686589760b4e25");
    }
}
