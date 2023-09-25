package dev.medzik.libcrypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public final class Argon2Tests {
    @Test
    void testHash() {
        Argon2 argon2 = new Argon2.Builder()
                .setHashLength(32)
                .setIterations(4)
                .setMemory(65536)
                .setParallelism(4)
                .setType(Argon2Type.ID)
                .setVersion(Argon2.ARGON2_VERSION_13)
                .build();

        Argon2Hash hash = argon2.hash("secret password", Random.randBytes(16));

        assertTrue(Argon2.verify("secret password", hash.toString()));
        // invalid password
        assertFalse(Argon2.verify("invalid password", hash.toString()));
    }

    @Test
    void testValidHash() {
        String hash = "$argon2id$v=19$m=15360,t=2,p=1$bWVkemlrQGR1Y2suY29t$n7wCfzdczbjclMnpvw+t/4D+mCcCFUU+hm6Z85k81PQ";

        assertTrue(Argon2.verify("medzik@duck.com", hash));
    }
}
