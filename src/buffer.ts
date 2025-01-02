import { zipSync, type Zippable } from 'fflate/browser'

export interface ZipConvertible {
    toZipStructure(): Zippable
}

export function toUint8Array(zc: ZipConvertible) {
    return zipSync(zc.toZipStructure())
}