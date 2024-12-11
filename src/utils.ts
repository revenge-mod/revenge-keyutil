export function u64ToU8Array(bigInt: bigint) {
    const buffer = new ArrayBuffer(8)
    const view = new DataView(buffer)

    view.setBigUint64(0, bigInt)

    return new Uint8Array(buffer)
}

export function u8ArrayToU64(u8: Uint8Array) {
    const view = new DataView(u8.buffer)
    return view.getBigUint64(0)
}

export function toKeyId(u8: Uint8Array) {
    return toHex(u8).toUpperCase().slice(-16)
}

export function toHex(u8: Uint8Array) {
    return Array.from(u8)
        .map(i => i.toString(16).padStart(2, '0'))
        .join('')
}

export function bufToString(buf: AllowSharedBufferSource) {
    return new TextDecoder().decode(buf)
}

export function strToU8(str: string) {
    return new TextEncoder().encode(str)
}
