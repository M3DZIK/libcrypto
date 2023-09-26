import * as aes from "./aes";

describe("AES", () => {
    test("CBC Encrypt and Decrypt", async () => {
        const secretKey = "82fd4cefd6efde36171900b469bae4e06863cb70f80b4e216e44eeb0cf30460b"
        const clearText = "Hello World!"

        const cipherText = aes.encryptAesCbc(secretKey, clearText)
        const decryptedText = aes.decryptAesCbc(secretKey, cipherText)

        expect(decryptedText).toBe(clearText)
    })

    test("CBC Decrypt", () => {
        const secretKey = "82fd4cefd6efde36171900b469bae4e06863cb70f80b4e216e44eeb0cf30460b"
        const cipherText = "ae77d812f4494a766a94b5dff8e7aa3c8408544b9fd30cd13b886cc5dd1b190e";

        const decryptedText = aes.decryptAesCbc(secretKey, cipherText)

        expect(decryptedText).toBe("hello world")
    })

    test("GCM Encrypt and Decrypt", async () => {
        const secretKey = "82fd4cefd6efde36171900b469bae4e06863cb70f80b4e216e44eeb0cf30460b"
        const clearText = "Hello World!"

        const cipherText = aes.encryptAesGcm(secretKey, clearText)
        const decryptedText = aes.decryptAesGcm(secretKey, cipherText)

        expect(decryptedText).toBe(clearText)
    })

    test("GCM Decrypt", () => {
        const secretKey = "82fd4cefd6efde36171900b469bae4e06863cb70f80b4e216e44eeb0cf30460b"
        const cipherText = "0996c65a72a60e748415dc6d32da1d4dcb65f41c71d4bec9554424218839b5d4b9d9195e5eea9d";

        const decryptedText = aes.decryptAesGcm(secretKey, cipherText)

        expect(decryptedText).toBe("hello world")
    })
})
