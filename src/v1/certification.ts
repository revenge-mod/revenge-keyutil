import { verify } from '@noble/ed25519'

import type { Key, KeyID, Signature } from '../shared'

export interface RevengeCertificationV1Options {
    certifierPublicId: KeyID
    signature: Signature
    holderSignature: Signature
}

export class RevengeCertificationV1 {
    certifierPublicId: KeyID
    signature: Signature
    holderSignature: Signature

    constructor({
        certifierPublicId,
        signature: certifierSignature,
        holderSignature,
    }: RevengeCertificationV1Options) {
        this.certifierPublicId = certifierPublicId
        this.signature = certifierSignature
        this.holderSignature = holderSignature
    }

    isValid(certifierPublicKey: Key) {
        return verify(this.signature, this.holderSignature, certifierPublicKey)
    }
}
