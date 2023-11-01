package dev.medzik.libcrypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public final class Argon2Tests {
    @Test
    void testHash() {
        Argon2.Builder argon2Builder = new Argon2.Builder()
                .setHashLength(32)
                .setIterations(4)
                .setMemory(65536)
                .setParallelism(4)
                .setType(Argon2Type.ID);

        Argon2Hash hashV13 = argon2Builder
                .setVersion(Argon2.ARGON2_VERSION_13)
                .build()
                .hash("secret password", Random.randBytes(16));

        assertTrue(Argon2.verify("secret password", hashV13.toString()));
        // invalid password
        assertFalse(Argon2.verify("invalid password", hashV13.toString()));

        Argon2Hash hashV10 = argon2Builder
                .setVersion(Argon2.ARGON2_VERSION_10)
                .build()
                .hash("secret password", Random.randBytes(16));

        assertTrue(Argon2.verify("secret password", hashV10.toString()));
        // invalid password
        assertFalse(Argon2.verify("invalid password", hashV10.toString()));

        assertNotEquals(hashV13, hashV10);
    }

    @Test
    void testValidHash() {
        String hash = "$argon2id$v=19$m=15360,t=2,p=1$bWVkemlrQGR1Y2suY29t$n7wCfzdczbjclMnpvw+t/4D+mCcCFUU+hm6Z85k81PQ";

        assertTrue(Argon2.verify("medzik@duck.com", hash));
    }
}
