package dev.medzik.libcrypto;

import com.password4j.Argon2Function;
import com.password4j.Hash;
import com.password4j.Password;

public final class Argon2 {
    private final int hashLength;
    private final int parallelism;
    private final int memory;
    private final int iterations;
    private final Argon2Type type;
    private final int version;

    public static final int ARGON2_VERSION_10 = 0x10;
    public static final int ARGON2_VERSION_13 = 0x13;

    public final static class Builder {
        private int hashLength;
        private int parallelism;
        private int memory;
        private int iterations;
        private Argon2Type type;
        private int version;

        public Builder() {
            this.hashLength = 32;
            this.parallelism = 1;
            this.memory = 65536;
            this.iterations = 3;
            this.type = Argon2Type.ID;
            this.version = ARGON2_VERSION_13;
        }

        public Builder setHashLength(int hashLength) {
            this.hashLength = hashLength;
            return this;
        }

        public Builder setParallelism(int parallelism) {
            this.parallelism = parallelism;
            return this;
        }

        public Builder setMemory(int memory) {
            this.memory = memory;
            return this;
        }

        public Builder setIterations(int iterations) {
            this.iterations = iterations;
            return this;
        }

        public Builder setType(Argon2Type type) {
            this.type = type;
            return this;
        }

        public Builder setVersion(int version) {
            this.version = version;
            return this;
        }

        public Argon2 build() {
            return new Argon2(hashLength, parallelism, memory, iterations, type, version);
        }
    }

    /**
     * Creates a new instance of Argon2 hasher with the given parameters.
     * @param hashLength length of the hash
     * @param parallelism number of parallel threads to use when hashing
     * @param memory amount of memory to use when hashing
     * @param iterations number of iterations to use when hashing
     */
    public Argon2(int hashLength, int parallelism, int memory, int iterations) {
        this.hashLength = hashLength;
        this.parallelism = parallelism;
        this.memory = memory;
        this.iterations = iterations;
        this.type = Argon2Type.ID;
        this.version = ARGON2_VERSION_13;
    }

    /**
     * Creates a new instance of Argon2 hasher with the given parameters.
     * @param hashLength length of the hash
     * @param parallelism number of parallel threads to use when hashing
     * @param memory amount of memory to use when hashing
     * @param iterations number of iterations to use when hashing
     * @param type type argon2 to use (i, d, id) {@link Argon2Type}
     * @param version hasher version
     */
    public Argon2(int hashLength, int parallelism, int memory, int iterations, Argon2Type type, int version) {
        this.hashLength = hashLength;
        this.parallelism = parallelism;
        this.memory = memory;
        this.iterations = iterations;
        this.type = type;
        this.version = version;
    }

    /** Hashes the given password. */
    public Argon2Hash hash(String password, byte[] salt) {
        Argon2Function instance = Argon2Function.getInstance(
            memory,
            iterations,
            parallelism,
            hashLength,
            type.toPassword4jType(),
            version
        );

        Hash hash = Password
                .hash(password)
                .addSalt(salt)
                .with(instance);

        return Argon2EncodingUtils.decode(hash.getResult());
    }

    /** Verifies a password against a hash. */
    public static boolean verify(CharSequence rawPassword, String encodedPassword) {
        // decode the `encodedPassword` to get the parameters
        Argon2Hash argon2Hash = Argon2EncodingUtils.decode(encodedPassword);

        Argon2Function instance = Argon2Function.getInstance(
                argon2Hash.getMemory(),
                argon2Hash.getIterations(),
                argon2Hash.getParallelism(),
                argon2Hash.getHashLength(),
                argon2Hash.getType().toPassword4jType(),
                argon2Hash.getVersion()
        );

        return Password
                .check(rawPassword, encodedPassword)
                .with(instance);
    }
}
