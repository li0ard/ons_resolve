import { test, expect } from 'bun:test'
import { resolve } from '../src/index'

test('resolve modern format', async () => {
    expect(await resolve('li0ard')).toBe('05fc331b505085fecc2188707c1da8002ee3edc6eb5591e36ded40a4669a94ab11')
    expect(await resolve('hloth')).toBe('057aeb66e45660c3bdfb7c62706f6440226af43ec13f3b6f899c1dd4db1b8fce5b')
    expect(await resolve('keejef')).toBe('05d871fc80ca007eed9b2f4df72853e2a2d5465a92fcb1889fb5c84aa2833b3b40')
})
  
test('resolve legacy format', async () => {
    expect(await resolve('sissi')).toBe('05bf7d78abf034661c691523b009ea2a281ee9c2093009808e098399e49fa1c54f')
    expect(await resolve('costa')).toBe('05bf7d78abf034661c691523b009ea2a281ee9c2093009808e098399e49fa1c54f')
    expect(await resolve('tinder')).toBe('0563854b4dbf5ccaddbd077f91b40e93fa9d095582027bfaabc36e3b821c4e4f04')
})
  