import { zipSync } from 'fflate/browser'

export interface ZipConvertible {
    toZipStructure(): Record<string, Uint8Array>
}

export function toUint8Array(zc: ZipConvertible) {
    return zipSync(zc.toZipStructure())
}