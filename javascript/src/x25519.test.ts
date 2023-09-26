import * as x25519 from "./x25519"

describe("X25519", () => {
    test("Generate Key Pair", async () => {
        const keyPair = x25519.generateKeyPair();

        expect(keyPair.privateKey).toHaveLength(64)
        expect(keyPair.publicKey).toHaveLength(64)
    })

    test("Compute Shared Secret", () => {
        const privateKey = "3845bead1f44408ee436c742291f1362489eeaaa9daebd480b1c3e4bc528cb48"
        const publicKey = "9d49b72cf49defc6748c67ab274a1c2f096362ef3b2d691793686589760b4e25"

        const sharedSecret = x25519.computeSharedSecret(privateKey, publicKey)

        expect(sharedSecret).toBe("2bebf3c397ab3c79db9aeeb2c1523ab4a32bd1ae335a19cd47e35983a5184d09")
    })

    test("Public Key from Private Key", () => {
        const privateKey = "3845bead1f44408ee436c742291f1362489eeaaa9daebd480b1c3e4bc528cb48"

        const publicKey = x25519.publicFromPrivate(privateKey)

        expect(publicKey).toBe("9d49b72cf49defc6748c67ab274a1c2f096362ef3b2d691793686589760b4e25")
    })
})
