import { Buffer } from "buffer/"
import * as curve25519 from "@stablelib/x25519"

/** Generate a new Curve25519 key pair. */
export function generateKeyPair() {
    const keyPair = curve25519.generateKeyPair();

    return {
        privateKey: bytesToHex(keyPair.secretKey),
        publicKey: bytesToHex(keyPair.publicKey)
    }
}

/**
 * Computes a 32-byte shared secret between two users.
 * @param ourPrivate 32-byte private key
 * @param theirPublic 32-byte public key
 * @return string 32-byte shared secret
 */
export function computeSharedSecret(ourPrivate: string, theirPublic: string) {
    const sharedSecret = curve25519.sharedKey(hexToBuffer(ourPrivate), hexToBuffer(theirPublic));

    return bytesToHex(sharedSecret);
}

/**
 * Recovers public key from a private key
 * @param privateKey 32-byte private key
 * @return string 32-byte public key
 */
export function publicFromPrivate(privateKey: string) {
    const publicKey = curve25519.scalarMultBase(hexToBuffer(privateKey));

    return bytesToHex(publicKey);
}

function hexToBuffer(hex: string) {
    return Buffer.from(hex, 'hex');
}

function bytesToHex(bytes: Uint8Array) {
    return Buffer.from(bytes).toString('hex');
}
