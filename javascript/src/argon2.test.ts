import * as argon2 from "./argon2";
import * as random from "./random";

describe("Argon2", () => {
    test('Hash', async () => {
        // argon2i
        const hashI = await argon2.I({
            hashLength: 256 / 8, // 256 bits
            iterations: 1,
            memorySize: 65536,
            parallelism: 1,
            password: 'password',
            salt: random.randBytes(16),
        })
        expect(hashI).toEqual(expect.any(String))

        // argon2d
        const hashD = await argon2.D({
            hashLength: 256 / 8, // 256 bits
            iterations: 1,
            memorySize: 65536,
            parallelism: 1,
            password: 'password',
            salt: random.randBytes(16),
        })
        expect(hashD).toEqual(expect.any(String))

        // argon2id
        const hashID = await argon2.ID({
            hashLength: 256 / 8, // 256 bits
            iterations: 1,
            memorySize: 65536,
            parallelism: 1,
            password: 'password',
            salt: random.randBytes(16),
        })
        expect(hashID).toEqual(expect.any(String))
    })

    test("Valid hash", async () => {
        const hash = "$argon2id$v=19$m=15360,t=2,p=1$bWVkemlrQGR1Y2suY29t$n7wCfzdczbjclMnpvw+t/4D+mCcCFUU+hm6Z85k81PQ"

        const valid = await argon2.verify({
            hash,
            password: 'medzik@duck.com',
        })

        expect(valid).toBe(true);
    })
})
