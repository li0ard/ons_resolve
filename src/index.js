const libsodiumwrappers = require('libsodium-wrappers-sumo');
const bytebuffer = require('bytebuffer');

async function getSodiumRenderer() {
    await libsodiumwrappers.ready;
    return libsodiumwrappers;
}

function encode(value, encoding) {
    return bytebuffer.wrap(value, encoding).toArrayBuffer();
}
function decode(buffer, stringEncoding) {
    return bytebuffer.wrap(buffer).toString(stringEncoding);
}
const fromUInt8ArrayToBase64 = (d) => decode(d, 'base64');
const toHex = (d) => decode(d, 'hex');
const fromHex = (d) => encode(d, 'hex');
const fromHexToArray = (d) => new Uint8Array(fromHex(d));

const stringToUint8Array = (str) => {
    if (!str) {
        return new Uint8Array();
    }
    return new Uint8Array(encode(str, 'binary'));
}

async function resolve(onsNameCase) {
    const onsNameLowerCase = onsNameCase.toLowerCase();
    const sodium = await getSodiumRenderer();
    const nameAsData = stringToUint8Array(onsNameLowerCase);
    const nameHash = sodium.crypto_generichash(sodium.crypto_generichash_BYTES, nameAsData);
    let base64EncodedNameHash = fromUInt8ArrayToBase64(nameHash);
    var rpc_req = await fetch('http://public-na.optf.ngo:22023/json_rpc', {
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
                'name_hash': base64EncodedNameHash
            }
        })
    })
    rpc_req = await rpc_req.json()
    if(!rpc_req.result.encrypted_value) {
        throw new Error('ons_resolve: No encrypted_value, maybe not found');
    }

    const hexEncodedCipherText = rpc_req.result.encrypted_value;
    const isArgon2Based = !Boolean(rpc_req.result.nonce);
    const ciphertext = fromHexToArray(hexEncodedCipherText);
    let sessionIDAsData;
    let nonce;
    let key;
    if (isArgon2Based) {
        const salt = new Uint8Array(sodium.crypto_pwhash_SALTBYTES);
        nonce = new Uint8Array(sodium.crypto_secretbox_NONCEBYTES)
        try {
            const keyHex = sodium.crypto_pwhash(sodium.crypto_secretbox_KEYBYTES, onsNameLowerCase, salt, sodium.crypto_pwhash_OPSLIMIT_MODERATE, sodium.crypto_pwhash_MEMLIMIT_MODERATE, sodium.crypto_pwhash_ALG_ARGON2ID13, 'hex');
            if (!keyHex) {
                throw new Error('ons_resolve: key invalid argon2');
            }
            key = fromHexToArray(keyHex);
        } catch (e) {
            throw new Error('ons_resolve: Hashing failed');
        }

        sessionIDAsData = sodium.crypto_secretbox_open_easy(ciphertext, nonce, key);
        if (!sessionIDAsData) {
            throw new Error('ons_resolve: Decryption failed');
        }
        return toHex(sessionIDAsData)
    }
    else {
        const hexEncodedNonce = rpc_req.result.nonce;
        if (!hexEncodedNonce) {
            throw new Error('ons_resolve: No hexEncodedNonce');
        }
        nonce = fromHexToArray(hexEncodedNonce);
        try {
            key = sodium.crypto_generichash(sodium.crypto_generichash_BYTES, nameAsData, nameHash);
            if (!key) {
                throw new Error('ons_resolve: Hashing failed');
            }
        }
        catch (e) {
            throw new Error('ons_resolve: Hashing failed');
        }
        sessionIDAsData = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, null, nonce, key);

        if (!sessionIDAsData) {
            throw new Error('ons_resolve: Decryption failed');
        }

        return toHex(sessionIDAsData)
    }
}

module.exports = resolve