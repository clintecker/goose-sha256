// FIPS 180-4's examples (NIST's "SHA256.pdf" and the long-message vector),
// and one input fed in pieces of several sizes. Run from the package root:
// goose run test/vectors_test.goose
import std;
import sha256 from "..";

fn hexof(h: u32[8]) -> u8[>..] {
    var out: u8[>..] = [];
    sha256::hex(out, h);
    return out;
}

// `msg` added `piece` bytes at a time.
fn in_pieces(msg: const u8[:], piece: i64) -> u8[>..] {
    var s = sha256::start();
    var i = 0;
    while i < msg.len { let j = min(i + piece, msg.len); sha256::add(s, msg[i..j]); i = j; }
    return hexof(sha256::finish(s));
}

fn main() {
    assert(hexof(sha256::digest("")) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert(hexof(sha256::digest("abc")) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    let two = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";     // 448 bits
    assert(hexof(sha256::digest(two)) == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    var million: u8[>..] = [];
    for i in 1000000 { million.push('a'); }
    let want = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";
    assert(hexof(sha256::digest(million)) == want);
    for piece in [1, 63, 64, 65, 4096] { assert(in_pieces(million, piece) == want); }
    for piece in [1, 55, 56, 57, 63, 64] { assert(in_pieces(two, piece) == hexof(sha256::digest(two))); }
}
