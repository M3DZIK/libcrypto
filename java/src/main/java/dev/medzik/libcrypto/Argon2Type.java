package dev.medzik.libcrypto;

import com.password4j.types.Argon2;

public enum Argon2Type {
    D,
    I,
    ID;

    public Argon2 toPassword4jType() {
        switch (this) {
            case D:
                return Argon2.D;
            case I:
                return Argon2.I;
            case ID:
                return Argon2.ID;
        }
        // never happens
        return null;
    }
}
