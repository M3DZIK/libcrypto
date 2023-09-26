import { Buffer } from "buffer/"

/**
 * Generate a random byte array of the given length
 * @param length The length of the salt to generate
 */
export function randBytes(length: number): Buffer {
    const salt: number[] = []
    for (let i = 0; i < length; i++) {
        salt.push(Math.floor(Math.random() * 255))
    }

    return Buffer.from(salt)
}
