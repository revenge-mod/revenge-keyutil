import { verify } from '@noble/ed25519'
import { sha512 } from '@noble/hashes/sha512'
import { zipSync, type Zippable } from 'fflate/browser'

import { KeyType } from '../shared'
import { strToU8, toKeyId, u64ToU8Array } from '../utils'

import type { Key, KeyID, SpecVersion, Signature } from '../shared'
import type { RevengeCertificationV1 } from './certification'
import type { RevengePrivateKeyV1 } from './private'
import type { ZipConvertible } from '../buffer'

export interface RevengePublicKeyV1Options {
    info: RevengePublicKeyV1Info
    key: Key
    certifications: Record<KeyID, RevengeCertificationV1>
    signature: Signature
}

export interface RevengePublicKeyV1Info {
    name: string
    expires: bigint
}

type InternalPublicKeyV1Info = Record<'n' | 'e', Uint8Array>

type InternalPublicKeyV1Certifications = Record<KeyID, Signature>

type InternalPublicKeyV1 = {
    k: Key
    i: Uint8Array
    is: Signature
    c: Uint8Array
    t: Uint8Array
}

export class RevengePublicKeyV1 implements ZipConvertible {
    type = KeyType.Public as const
    info: RevengePublicKeyV1Info
    signature: Signature
    certifications: Record<KeyID, RevengeCertificationV1>
    key: Key
    id: KeyID
    version: SpecVersion = 1

    constructor({ info, key, certifications, signature }: RevengePublicKeyV1Options) {
        this.info = info
        this.signature = signature
        this.certifications = certifications
        this.key = key
        this.id = toKeyId(sha512(key)).toString().slice(-16)
    }

    toZipStructure() {
        return {
            k: this.key,
            i: zipSync(RevengePublicKeyV1.infoToZipStructure(this.info)),
            is: this.signature,
            c: zipSync(
                Object.fromEntries(Object.entries(this.certifications).map(([id, cert]) => [id, cert.signature])),
            ),
            t: new Uint8Array([(this.version << 4) | (this.type & 0x0f)]),
        } satisfies InternalPublicKeyV1
    }

    isValid() {
        return this.verify(this.signature, RevengePublicKeyV1.infoToSignatureDataUint8Array(this.info))
    }

    verify(signature: Signature, data: Uint8Array | string) {
        if (this.expired) return false
        return verify(signature, data, this.key)
    }

    static infoToZipStructure(info: RevengePublicKeyV1Info): Zippable {
        return {
            n: strToU8(info.name),
            e: u64ToU8Array(info.expires),
        } satisfies InternalPublicKeyV1Info
    }

    static infoToSignatureDataUint8Array(info: RevengePublicKeyV1Info) {
        return sha512(zipSync(RevengePublicKeyV1.infoToZipStructure(info)))
    }

    get expired() {
        return Math.round(Date.now() / 1000) > this.info.expires
    }

    isPublic(): this is RevengePublicKeyV1 {
        return true
    }

    isPrivate(): this is RevengePrivateKeyV1 {
        return false
    }
}
