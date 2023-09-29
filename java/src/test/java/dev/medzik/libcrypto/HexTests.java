package dev.medzik.libcrypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public final class HexTests {
    @Test
    public void testHex() {
        String hexString = "48656c6c6f20576f726c6421";
        String expected = "Hello World!";
        assertEquals(expected, new String(Hex.decode(hexString)));
        assertEquals(expected, new String(Hex.decode(hexString.toUpperCase())));

        String encoded = Hex.encode(expected.getBytes());
        assertEquals(hexString, encoded.toLowerCase());
    }
}
