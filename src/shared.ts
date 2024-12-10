export type Signature = Uint8Array
export type KeyID = string
export type Key = Uint8Array

export type SpecVersion = 1

export enum KeyType {
    Public = 1,
    Private = 2,
}

export const KeySize = 32
export const SignatureSize = 64
