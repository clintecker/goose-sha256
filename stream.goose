// The SHA-256 of an open file or stdin, read 64 KB at a time through
// clintecker/goose-file, so memory stays the same whatever the input's size.
// `import sha256.stream;`; the program's root also declares the file package.
namespace sha256;
import std;
import file from "clintecker/goose-file@v1";

// Bytes read at a time: a multiple of the 64-byte block, so add() keeps no
// partial block between reads but the last.
let CHUNK = 1 << 16;

// The digest of the stream `f` (a goose-file handle) into `h`; false on a
// read error.
fn stream(f: u64, h: u32[8]&) -> bool {
    var s = start();
    var buf: u8[>..] = [];
    loop {
        buf.clear();
        let n = file::file_read(f, CHUNK, buf);
        if n < 0 { return false; }
        if n == 0 { break; }
        add(s, buf);
    }
    h = finish(s);
    return true;
}
