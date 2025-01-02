import { verify } from '@noble/ed25519'

import { strToU8 } from '../utils'

import type { SpecVersion } from '../shared'
import type { ZipConvertible } from '../buffer'

export interface RevengeSignatureV1Options {
    signerPublicId: string
    signature: Uint8Array
}

interface InternalRevengeSignatureV1 {
    i: Uint8Array
    s: Uint8Array
}

export class RevengeSignatureV1 implements ZipConvertible {
    signerPublicId: string
    signature: Uint8Array
    version: SpecVersion = 1

    constructor({ signerPublicId, signature }: RevengeSignatureV1Options) {
        this.signerPublicId = signerPublicId
        this.signature = signature
    }

    toZipStructure() {
        return {
            i: strToU8(this.signerPublicId),
            s: this.signature,
        } satisfies InternalRevengeSignatureV1
    }

    verify(publicKey: Uint8Array, data: Uint8Array) {
        return verify(this.signature, data, publicKey)
    }
}
