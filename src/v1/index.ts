import * as ed from '@noble/ed25519'
import { sha512 } from '@noble/hashes/sha512'
import { unzipSync } from 'fflate/browser'

import { RevengeCertificationV1 } from './certification'
import { RevengePrivateKeyV1 } from './private'
import { RevengePublicKeyV1 } from './public'
import { RevengeSignatureV1 } from './signature'

import { KeySize, KeyType, SignatureSize } from '../shared'
import { u8ArrayToU64, bufToString } from '../utils'

ed.etc.sha512Sync = sha512

export * from './certification'
export * from './private'
export * from './public'
export * from './signature'

export interface CreateRevengeKeyPairOptions {
    name: string
    expires: bigint
}

export function createRevengeKeyPair({ name, expires }: CreateRevengeKeyPairOptions) {
    const pvKey = ed.utils.randomPrivateKey()
    const pbKey = ed.getPublicKey(pvKey)

    const rPvKey = new RevengePrivateKeyV1({
        info: {
            publicKey: pbKey,
            publicKeyInfo: {
                name,
                expires,
            },
        },
        key: pvKey,
    })

    const rPbKey = rPvKey.createPublicKey()

    return {
        privateKey: rPvKey,
        publicKey: rPbKey,
    }
}

export function readRevengeKey(key: Uint8Array) {
    const { t, k, i, is, c } = unzipSync(key)

    if (!t || t.length !== 1 || !k || k.length !== KeySize || !i || !is || is.length !== SignatureSize)
        throw new Error('Invalid key file format')

    const { pi, pis, n, e } = unzipSync(i)

    const version = (t[0] >> 4) & 0x0f
    const type = t[0] & 0x0f

    if (version !== 1) throw new Error('Unsupported key version')

    switch (type) {
        case KeyType.Private: {
            if (!pi || !pis) throw new Error('Invalid private key file format')

            const pk = ed.getPublicKey(k)

            if (!RevengePublicKeyV1.prototype.verify.call({ key: pk }, pis, sha512(pi)))
                throw new Error("Public key information's signature could not be verified")

            const { n, e } = unzipSync(pi)

            return new RevengePrivateKeyV1({
                key: k,
                info: {
                    publicKey: pk,
                    publicKeyInfo: {
                        name: bufToString(n),
                        expires: u8ArrayToU64(e),
                    },
                },
            })
        }

        case KeyType.Public: {
            if (!n || !e || !c) throw new Error('Invalid public key file format')

            const certs = unzipSync(c)

            return new RevengePublicKeyV1({
                key: k,
                certifications: Object.fromEntries(
                    Object.entries(certs).map(([pkId, signature]) => [
                        pkId,
                        new RevengeCertificationV1({ certifierPublicId: pkId, signature, holderSignature: is }),
                    ]),
                ),
                signature: is,
                info: {
                    name: bufToString(n.buffer as ArrayBuffer),
                    expires: u8ArrayToU64(e),
                },
            })
        }

        default:
            throw new Error('Unsupported key type')
    }
}

export function readRevengeSignature(signature: Uint8Array) {
    const { s, i } = unzipSync(signature)
    if (!s || !i) throw new Error('Invalid signature file format')

    return new RevengeSignatureV1({
        signerPublicId: bufToString(i),
        signature: s,
    })
}
