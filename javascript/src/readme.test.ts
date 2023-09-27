import { aes, argon2, random, x25519 } from "./";

describe("Readme Examples", () => {
    test("Aes", () => {
        const clearText = "hello world";
        // Key used for encryption (for example, argon2 hash in hex string)
        const secretKey = "82fd4cefd6efde36171900b469bae4e06863cb70f80b4e216e44eeb0cf30460b";

        // Encrypt using AES-GCM (AES-CBC is also available)
        const cipherText = aes.encryptAesGcm(secretKey, clearText);

        // Decrypt cipher text
        const decryptText = aes.decryptAesGcm(secretKey, cipherText);

        expect(decryptText).toBe(clearText);
    })

    test("Argon2", async () => {
        // Compute a hash of password with random 16-byte salt
        const hash = await argon2.ID({
            hashLength: 32,
            iterations: 4,
            memorySize: 65536,
            parallelism: 4,
            password: 'secret password',
            salt: random.randBytes(16),
        });

        // Hash is a hex encoded string, can be used to Aes encrypt

        expect(hash).toHaveLength(32 * 2);
    })

    test("X25519 Exchange Keys", () => {
        const bobKeyPair = x25519.generateKeyPair();
        const aliceKeyPair = x25519.generateKeyPair();

        // Bob sends "hello world" to Alice

        // Compute shared secret between Bob and Alice
        const sharedSecret_bob = x25519.computeSharedSecret(bobKeyPair.privateKey, aliceKeyPair.publicKey);

        // Encrypt message
        const message = "hello world";
        const encryptedMessage = aes.encryptAesGcm(sharedSecret_bob, message);

        // Alice decrypts a message from Bob

        // The same as `sharedSecret_bob`
        const sharedSecret_alice = x25519.computeSharedSecret(aliceKeyPair.privateKey, bobKeyPair.publicKey);

        // Decrypt message
        const decryptedMessage = aes.decryptAesGcm(sharedSecret_alice, encryptedMessage);

        expect(decryptedMessage).toBe(message)
    })
})
