package dev.medzik.libcrypto;

/**
 * Object representation of argon2 hash.
 */
public final class Argon2Hash {
    private final Argon2Type type;
    private final int version;
    private final int memory;
    private final int iterations;
    private final int parallelism;

    private final byte[] salt;
    private final byte[] hash;

    public Argon2Hash(Argon2Type type, int version, int memory, int iterations, int parallelism, byte[] salt, byte[] hash) {
        this.type = type;
        this.version = version;
        this.memory = memory;
        this.iterations = iterations;
        this.parallelism = parallelism;
        this.salt = salt;
        this.hash = hash;
    }

    /** Returns the Argon2 type of this hash. */
    public Argon2Type getType() {
        return type;
    }

    /** Returns argon2 version. */
    public int getVersion() {
        return version;
    }

    /** Returns memory parameter of this hash. */
    public int getMemory() {
        return memory;
    }

    /** Returns iteration parameter of this hash. */
    public int getIterations() {
        return iterations;
    }

    /** Returns parallelism parameter of this hash. */
    public int getParallelism() {
        return parallelism;
    }

    /** Returns salt of this hash. */
    public byte[] getSalt() {
        return salt;
    }

    /** Returns hash. */
    public byte[] getHash() {
        return hash;
    }

    /** Returns the hash length. */
    public int getHashLength() {
        return hash.length;
    }

    /** Returns hash in encoded format. */
    public String toArgon2String() {
        return Argon2EncodingUtils.encode(this);
    }

    /** Returns hash in encoded format Same as {@link #toArgon2String()}. */
    @Override
    public String toString() {
        return toArgon2String();
    }
}
