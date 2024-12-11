import { sign } from '@noble/ed25519'
import { sha512 } from '@noble/hashes/sha512'
import { encode } from 'uzip'

import { KeyType } from '../shared'
import { toKeyId } from '../utils'
import { RevengeCertificationV1 } from './certification'
import { RevengePublicKeyV1, type RevengePublicKeyV1Info } from './public'

import type { Key, KeyID, SpecVersion, Signature } from '../shared'
import { RevengeSignatureV1 } from './signature'

export interface RevengePrivateKeyV1Info {
    publicKey: Key
    publicKeyInfo: RevengePublicKeyV1Info
}

export interface RevengePrivateKeyV1OptionsInfo {
    publicKey: Key
    publicKeyInfo: RevengePublicKeyV1Info
}

export interface RevengePrivateKeyV1Options {
    info: RevengePrivateKeyV1OptionsInfo
    key: Key
}

type InternalPrivateKeyV1Info = {
    pi: Uint8Array
    pis: Signature
}

type InternalPrivateKeyV1 = {
    k: Key
    i: Uint8Array
    is: Signature
    t: Uint8Array
}

export class RevengePrivateKeyV1 {
    type = KeyType.Private as const
    info: RevengePrivateKeyV1Info
    key: Key
    publicId: KeyID
    id: KeyID
    version: SpecVersion = 1

    constructor({ info, key }: RevengePrivateKeyV1Options) {
        this.info = info
        this.key = key
        this.publicId = toKeyId(sha512(info.publicKey)).toUpperCase().slice(-16)
        this.id = toKeyId(sha512(key)).toUpperCase().slice(-16)
    }

    get expired() {
        return Math.round(Date.now() / 1000) > this.info.publicKeyInfo.expires
    }

    #getPublicKeySignature() {
        return this.#sign(RevengePublicKeyV1.infoToSignatureDataUint8Array(this.info.publicKeyInfo))
    }

    toArrayBuffer() {
        const eInfo = encode({
            pi: new Uint8Array(RevengePublicKeyV1.infoToArrayBuffer(this.info.publicKeyInfo)),
            pis: this.#getPublicKeySignature(),
        } satisfies InternalPrivateKeyV1Info)

        const t = new Uint8Array([(this.version << 4) | (this.type & 0x0f)])

        return encode({
            k: this.key,
            i: new Uint8Array(eInfo),
            is: this.#sign(new Uint8Array(eInfo)),
            t,
        } satisfies InternalPrivateKeyV1)
    }

    sign(data: Uint8Array) {
        return new RevengeSignatureV1({ signature: this.#sign(data), signerPublicId: this.publicId })
    }

    #sign(data: Uint8Array) {
        if (this.expired) throw new Error('Cannot sign with expired key')
        return sign(data, this.key)
    }

    createPublicKey() {
        const pbKey = new RevengePublicKeyV1({
            key: this.info.publicKey,
            info: this.info.publicKeyInfo,
            signature: this.#getPublicKeySignature(),
            certifications: {},
        })

        this.certify(pbKey)

        return pbKey
    }

    certify(publicKey: RevengePublicKeyV1) {
        publicKey.certifications[this.publicId] = new RevengeCertificationV1({
            certifierPublicId: this.publicId,
            signature: this.#sign(publicKey.signature),
            holderSignature: publicKey.signature,
        })
    }

    isPublic(): this is RevengePublicKeyV1 {
        return false
    }

    isPrivate(): this is RevengePrivateKeyV1 {
        return true
    }
}
