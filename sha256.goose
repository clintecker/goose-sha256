// SHA-256 (FIPS 180-4) over bytes the caller already has: start a State,
// add bytes in pieces of any size, finish. The state is fixed-size arrays the
// caller owns: no allocation and no C. stream.goose (`import sha256.stream;`)
// reads an open file through clintecker/goose-file.
namespace sha256;
import std;

// The round constants: the first 32 bits of the fractional parts of the cube
// roots of the first 64 primes (FIPS 180-4 §4.2.2).
let K: u32[64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// The initial hash value (§5.3.3).
let H0: u32[8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

fn rotr(x: u32, n: u32) -> u32 { (x >> n) | (x << (32 - n)) }

// The message schedule for one 64-byte block (§6.2.2 step 1).
fn schedule(blk: const u8[:], w: u32[64]&) {
    for i in 16 {
        w[i] = (blk[4 * i] as u32) << 24 | (blk[4 * i + 1] as u32) << 16
             | (blk[4 * i + 2] as u32) << 8 | blk[4 * i + 3];
    }
    for i in 16..64 {
        let s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        let s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
}

// One block into the hash state (§6.2.2 steps 2-4). u32 arithmetic wraps,
// which is the addition modulo 2^32 the standard asks for.
fn compress(h: u32[8]&, blk: const u8[:], w: u32[64]&) {
    schedule(blk, w);
    var a = h[0]; var b = h[1]; var c = h[2]; var d = h[3];
    var e = h[4]; var f = h[5]; var g = h[6]; var k = h[7];
    for i in 64 {
        let t1 = k + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
        let t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        k = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += k;
}

// The padded tail after the last whole block: the leftover bytes, a 1 bit,
// zeros, and the message length in bits; one block, or two when fewer
// than 9 bytes of the last are free (§5.1.1).
fn tail_blocks(h: u32[8]&, rest: const u8[:], total: i64, w: u32[64]&) {
    var tail: u8[128] = [0; 128];
    for i in rest.len { tail[i] = rest[i]; }
    tail[rest.len] = 0x80;
    let n = if rest.len < 56 { 64 } else { 128 };
    let bits = (total as u64) * 8;
    for i in 8 { tail[n - 1 - i] = ((bits >> ((8 * i) as u64)) & 0xff) as u8; }
    compress(h, tail[..64], w);
    if n == 128 { compress(h, tail[64..], w); }
}

// A hash in progress: the chaining state, the message schedule's scratch,
// the partial block not yet compressed, and the bytes added so far.
struct State { h: u32[8], w: u32[64], part: u8[64], used: i64 = 0, total: i64 = 0 }

// A State with nothing added.
fn start() -> State {
    return State { h: H0, w: [0; 64], part: [0; 64] };
}

// Adds `bytes` to the hash: whole blocks straight from `bytes`, the rest kept
// in the State's part until a later add fills it.
fn add(s: State&, bytes: const u8[:]) {
    s.total += bytes.len;
    var i = 0;
    if s.used > 0 {
        while s.used < 64 && i < bytes.len { s.part[s.used] = bytes[i]; s.used++; i++; }
        guard s.used == 64 else { return; }
        compress(s.h, s.part[..], s.w);
        s.used = 0;
    }
    while bytes.len - i >= 64 { compress(s.h, bytes[i..i + 64], s.w); i += 64; }
    while i < bytes.len { s.part[s.used] = bytes[i]; s.used++; i++; }
}

// The digest of everything added. The State is spent afterwards.
fn finish(s: State&) -> u32[8] {
    tail_blocks(s.h, s.part[..s.used], s.total, s.w);
    return s.h;
}

// The digest of `bytes` in one call.
fn digest(bytes: const u8[:]) -> u32[8] {
    var s = start();
    add(s, bytes);
    return finish(s);
}

// A digest as 64 lowercase hex digits.
fn hex(out: u8[>..]&, h: u32[8]) {
    for x in h { format_uint(out, x, 16, 8, '0'); }
}
