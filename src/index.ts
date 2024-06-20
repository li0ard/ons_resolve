import sodium from 'libsodium-wrappers-sumo'
import { ready } from 'libsodium-wrappers-sumo'

export async function resolve(ons: string): Promise<string | null> {
    await ready
    if (!ons.match(/^\w([\w-]*[\w])?$/)) {
        throw new Error('Invalid ONS name')
    }
    ons = ons.toLowerCase()

    const onsBuffer = Buffer.from(ons)
    const nameHash = sodium.crypto_generichash(sodium.crypto_generichash_BYTES, onsBuffer);
    let request: any = await fetch('http://public-na.optf.ngo:22023/json_rpc', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            'jsonrpc': '2.0',
            'id': '0',
            'method': 'ons_resolve',
            'params': {
                'type': 0,
                'name_hash': Buffer.from(nameHash).toString("base64")
            }
        })
    })
    request = await request.json()
    if(!request.result.encrypted_value) {
        return null
    }
    const hexEncodedCipherText = request.result.encrypted_value;
    const ciphertext = Buffer.from(hexEncodedCipherText, "hex");

    if (!Boolean(request.result.nonce)) {
        let key = Buffer.from(sodium.crypto_pwhash(sodium.crypto_secretbox_KEYBYTES, ons, new Uint8Array(sodium.crypto_pwhash_SALTBYTES), sodium.crypto_pwhash_OPSLIMIT_MODERATE, sodium.crypto_pwhash_MEMLIMIT_MODERATE, sodium.crypto_pwhash_ALG_ARGON2ID13, 'hex'), "hex")
        return Buffer.from(sodium.crypto_secretbox_open_easy(ciphertext, new Uint8Array(sodium.crypto_secretbox_NONCEBYTES), key)).toString("hex")
    } else {
        let key = sodium.crypto_generichash(sodium.crypto_generichash_BYTES, onsBuffer, nameHash);
        return Buffer.from(sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, null, Buffer.from(request.result.nonce, "hex"), key)).toString("hex")
    }
}