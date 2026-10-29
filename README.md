# clintecker/goose-sha256

SHA-256 (FIPS 180-4) for [Goose](https://github.com/aardappel/goose). Add bytes in pieces of any size; the state is fixed-size arrays you own, so nothing is allocated and there is no C.

```goose
import sha256 from "clintecker/goose-sha256@v1";

var s = sha256::start();
sha256::add(s, "hello, ");
sha256::add(s, "world");
var out: u8[>..] = [];
sha256::hex(out, sha256::finish(s));   // 09ca7e4eaa6e8ae9c7d261167129184883644d07dfba7cbfbc4c8a2e08360d5b
```

`test/example.goose` is this example with asserts.

## Functions

| Function | What it does |
|---|---|
| `start() -> State` | a hash with nothing added |
| `add(s, bytes)` | adds bytes; whole 64-byte blocks are compressed straight from `bytes`, the rest waits in the State |
| `finish(s) -> u32[8]` | the digest of everything added; the State is spent afterwards |
| `digest(bytes) -> u32[8]` | `start`, `add`, `finish` in one call |
| `hex(out, h)` | appends a digest as 64 lowercase hex digits |
| `H0` | the initial hash value (FIPS 180-4 §5.3.3) |

`K`, `rotr`, `schedule`, `compress` and `tail_blocks` are the algorithm's steps; Goose has no private functions, so they are visible, but they are not part of the interface.

## Reading a file

`stream.goose` hashes an open file or stdin 64 KB at a time, so memory stays the same whatever the input's size. It reads through [clintecker/goose-file](https://github.com/clintecker/goose-file), so a program that uses it declares that package too:

```goose
import sha256 from "clintecker/goose-sha256@v1";
import sha256.stream;
import file from "clintecker/goose-file@v1";

var h: u32[8] = [0; 8];
let f = file::file_open("big.iso");
let ok = f != 0 && sha256::stream(f, h);   // false on a read error
```

A program that imports only `sha256` needs neither the file package nor its C.

## Tests

`test/*.goose` are assert programs, run from this directory with `goose run test/vectors_test.goose`: FIPS 180-4's examples ("", "abc", the 448-bit message, one million "a"), the same inputs added in pieces of 1 to 4096 bytes, and `stream` against `digest` on a file.

MIT licence (LICENSE).
