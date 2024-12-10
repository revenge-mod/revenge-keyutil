#! /usr/bin/env bun

import { sha512 } from '@noble/hashes/sha512'
import { readFileSync, writeFileSync } from 'fs'
import { program } from 'commander'

import { createRevengeKeyPair, readRevengeKey, readRevengeSignature } from './src/v1'
import { KeyType } from './src/shared'
import { toHex } from './src/utils'

program.name('revenge-keyutil').description('Utilities for working with Revenge keys')

program
    .command('new')
    .description('Create a new keypair')
    .alias('n')
    .requiredOption('-n, --name <name>', 'Name of keypair')
    .requiredOption('-e, --expires <date>', 'Key expiration date')
    .option('-pr, --private-key-path <path>', 'Path to private key', './private_key')
    .option('-pb, --public-key-path <path>', 'Path to public key', './public_key')
    .action(({ name, expires, privateKeyPath, publicKeyPath }) => {
        const { privateKey, publicKey } = createRevengeKeyPair({
            name,
            expires: BigInt(Math.floor(new Date(expires).getTime() / 1000)),
        })

        writeFileSync(privateKeyPath, Buffer.from(privateKey.toArrayBuffer()))
        writeFileSync(publicKeyPath, Buffer.from(publicKey.toArrayBuffer()))

        console.log(`Saved private key to ${privateKeyPath} and public key to ${publicKeyPath}`)
    })

program
    .command('sign')
    .description('Sign a file')
    .alias('s')
    .argument('<file>', 'Path to file')
    .requiredOption('-s, --signature, -o, --output <path>', 'Path to signature')
    .requiredOption('-k, -pr, --private-key-path, --key-path <path>', 'Path to private key of the signer')
    .action((filePath, { signature: signatureFilePath, Pr: keyPath }) => {
        const hash = sha512(readFileSync(filePath))
        const key = readRevengeKey(readFileSync(keyPath).buffer as ArrayBuffer)

        if (!key.isPrivate()) throw new Error('Key must be a private key')

        const signature = key.sign(hash)
        writeFileSync(signatureFilePath, Buffer.from(signature.toArrayBuffer()))

        console.log(`Signed ${filePath} and saved signature to ${signatureFilePath}`)
    })

program
    .command('verify')
    .description('Verify a signature')
    .alias('v')
    .argument('<file>', 'Path to file')
    .requiredOption('-s, --signature, -o, --output <path>', 'Path to signature')
    .requiredOption('-k, -pb, --public-key-path, --key-path <path>', 'Path to public key of the signer')
    .action((filePath, { signature: signatureFilePath, Pb: keyPath }) => {
        const hash = sha512(readFileSync(filePath))
        const signature = readRevengeSignature(readFileSync(signatureFilePath).buffer as ArrayBuffer)
        const key = readRevengeKey(readFileSync(keyPath).buffer as ArrayBuffer)

        if (!key.isPublic()) throw new Error('Key must be a public key')

        const isValid = key.verify(signature.signature, hash)
        console.log(`Signature is ${isValid ? 'valid' : 'invalid'}`)
    })

program
    .command('key-info')
    .description('Show information about a key')
    .aliases(['ki', 'keyinfo', 'kinfo'])
    .argument('<path>', 'Path to key/signature file')
    .option('-ls, --long-signatures, --long-signature', 'Show long signatures')
    .action((keyPath, { longSignatures }) => {
        const file = readFileSync(keyPath)
        const key = readRevengeKey(file.buffer as ArrayBuffer)

        console.log('')
        console.log(`Type: ${KeyType[key.type]}`)
        console.log('Version:', key.version)
        console.log('')

        if (key.isPublic()) {
            console.log(`Name: ${key.info.name}`)
            console.log(`ID: ${key.id}`)
            console.log(
                'Expires:',
                new Date(Number(key.info.expires) * 1000).toISOString(),
                `(${key.expired ? 'Expired' : 'Valid'})`,
            )

            console.log('')
            if (longSignatures) console.log(`Signature: ${toHex(key.signature)}`)
            else console.log(`Short-Signature: ${toHex(key.signature).slice(-32)}`)

            console.log('')
            console.log('Certifications:')
            const certs = Object.values(key.certifications)
            for (let i = 0; i < certs.length; i++) {
                const cert = certs[i]!
                const spaces = ' '.repeat(Math.log10(i + 1) + 3)
                console.log('')
                console.log(`${i + 1}. Certified-By: ${cert.certifierPublicId}`)
                if (longSignatures) console.log(`${spaces}Signature: ${toHex(cert.signature)}`)
                else console.log(`${spaces}Short-Signature: ${toHex(cert.signature).slice(-32)}`)
                if (cert.certifierPublicId === key.id) console.log(`${spaces}Valid: ${cert.isValid(key.key)}`)
            }
        } else {
            console.log(`Name: ${key.info.publicKeyInfo.name}`)
            console.log(`ID: ${key.id}`)
            console.log(
                'Expires:',
                new Date(Number(key.info.publicKeyInfo.expires) * 1000).toISOString(),
                `(${key.expired ? 'expired' : 'valid'})`,
            )
            console.log('')
            console.log(`Public-ID: ${key.publicId}`)
        }
    })

program
    .command('signature-info')
    .description('Show information about a signature')
    .aliases(['si', 'signatureinfo', 'sig-info', 'siginfo', 'sinfo'])
    .argument('<path>', 'Path to signature file')
    .action(path => {
        const file = readFileSync(path)
        const signature = readRevengeSignature(file.buffer as ArrayBuffer)

        console.log('')
        console.log(`Signed-By: ${signature.signerPublicId}`)
        console.log(`Signature: ${toHex(signature.signature)}`)
    })

program
    .command('certify')
    .description('Certify a public key')
    .aliases(['c', 'cert'])
    .argument('<public-key-path>', 'Path to public key')
    .requiredOption('-k, -pr, --private-key-path, --key-path <path>', 'Path to private key of the certifier')
    .action((publicKeyPath, { Pr }) => {
        const publicKeyFile = readFileSync(publicKeyPath)
        const privateKeyFile = readFileSync(Pr)

        const publicKey = readRevengeKey(publicKeyFile.buffer as ArrayBuffer)
        const privateKey = readRevengeKey(privateKeyFile.buffer as ArrayBuffer)

        if (!privateKey.isPrivate()) throw new Error('Key must be a private key')
        if (!publicKey.isPublic()) throw new Error('Key must be a public key')

        privateKey.certify(publicKey)

        writeFileSync(publicKeyPath, Buffer.from(publicKey.toArrayBuffer()))

        console.log(`Certified public key at ${publicKeyPath}`)
    })

program
    .command('certification-info')
    .description('Show information about a certification')
    .aliases(['ci', 'certinfo', 'cinfo'])
    .argument('<path>', 'Path to public key')
    .argument('<certifier-key-path>', "Path to the certifier's key")
    .option('-ls, --long-signatures, --long-signature', 'Show long signatures')
    .action((path, cPP, { longSignatures }) => {
        const file = readFileSync(path)
        const key = readRevengeKey(file.buffer as ArrayBuffer)
        const cKey = readRevengeKey(readFileSync(cPP).buffer as ArrayBuffer)
        const cPKeyId = cKey.isPublic() ? cKey.id : cKey.publicId

        if (!key.isPublic()) throw new Error('Certifee key must be a public key')

        console.log('')
        const cert = key.certifications[cPKeyId]
        if (!cert) return console.error(`${key.id} has not been certified by ${cPKeyId}`)

        console.log(`Certified-By: ${cert.certifierPublicId}`)
        if (longSignatures) console.log(`Signature: ${toHex(cert.signature)}`)
        else console.log(`Short-Signature: ${toHex(cert.signature).slice(-32)}`)
        console.log(`Valid: ${cert.isValid(cKey.isPrivate() ? cKey.info.publicKey : cKey.key)}`)
    })

program.parse()
