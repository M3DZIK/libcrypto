import { Buffer } from "buffer/"
import { createCipheriv, createDecipheriv } from "browserify-cipher"

import * as random from "./random"

const AES_CBC_MODE = 'aes-256-cbc'
const AES_GCM_MODE = 'aes-256-gcm'

/**
 * Encrypts a string using AES CBC mode
 * @param secretKey secret key to use for encryption (hex encoded)
 * @param clearText clear text to use for encryption
 * @return string cipher text (hex encoded)
 */
export function encryptAesCbc(secretKey: string, clearText: string): string {
    return encrypt(secretKey, clearText, AES_CBC_MODE, 16, false)
}

/**
 * Encrypts a string using AES GCM mode
 * @param secretKey secret key to use for encryption (hex encoded)
 * @param clearText clear text to use for encryption
 * @return string cipher text (hex encoded)
 */
export function encryptAesGcm(secretKey: string, clearText: string): string {
    return encrypt(secretKey, clearText, AES_GCM_MODE, 12, true)
}

/**
 * Decrypts the given cipher text using AES CBC mode with the given key.
 * @param secretKey secret key to use for encryption (hex encoded)
 * @param cipherText cipher text to decrypt (hex encoded)
 * @return string clear text (decrypted text)
 */
export function decryptAesCbc(secretKey: string, cipherText: string): string {
    return decrypt(secretKey, cipherText, AES_CBC_MODE, 16, false)
}

/**
 * Decrypts the given cipher text using AES GCM mode with the given key.
 * @param secretKey secret key to use for encryption (hex encoded)
 * @param cipherText cipher text to decrypt (hex encoded)
 * @return string clear text (decrypted text)
 */
export function decryptAesGcm(secretKey: string, cipherText: string): string {
    return decrypt(secretKey, cipherText, AES_GCM_MODE, 12, true)
}

function encrypt(secretKey: string, clearText: string, mode: string, ivLength: number, authMode: boolean) {
    // decode the secret key from a hex string to a buffer
    const key = Buffer.from(secretKey, 'hex')
    // generate a random initialization vector
    let iv = random.randBytes(ivLength)

    // create a cipher using the secret key and the initialization vector
    const cipher = createCipheriv(mode, key, iv)
    // update the cipher with the clear text
    let cipherText = cipher.update(clearText, 'utf8', 'hex')
    // finalize the cipher
    cipherText += cipher.final('hex')

    // add the initialization vector to the cipher text
    cipherText = Buffer.from(iv).toString('hex') + cipherText
    // if authentication is enabled, add auth tag to the cipher
    if (authMode) {
        cipherText += cipher.getAuthTag().toString('hex')
    }

    return cipherText
}

function decrypt(secretKey: string, cipherText: string, mode: string, ivLength: number, authMode: boolean) {
    // decode the secret key from a hex string to a buffer
    const key = Buffer.from(secretKey, 'hex')
    // get the initialization vector from the cipher text
    const iv = Buffer.from(cipherText.substring(0, ivLength * 2), 'hex')
    // remove the initialization vector from the cipher text
    cipherText = cipherText.substring(ivLength * 2)
    let authTag;
    if (authMode) {
        // get the auth tag from the cipher text
        authTag = Buffer.from(cipherText.substring(cipherText.length - 32), 'hex')
        // remove the auth tag from the cipher text
        cipherText = cipherText.substring(0, cipherText.length - 32)
    }

    // create decipheriv using the secret key and the initialization vector
    const cipher = createDecipheriv(mode, key, iv)
    if (authMode) {
        cipher.setAuthTag(authTag)
    }

    // update decipher with the cipher text
    let clearText = cipher.update(cipherText, 'hex', 'utf8');
    // finalize decipher
    clearText += cipher.final()

    return clearText
}
