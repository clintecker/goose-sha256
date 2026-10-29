// sha256::stream over a file agrees with sha256::digest of its bytes. Run
// from the package root: goose run test/stream_test.goose
import std;
import os;
import sha256 from "..";
import sha256.stream;
import file from "clintecker/goose-file@v1";

fn main() {
    var whole: u8[>..] = [];
    assert(read_file("sha256.goose", whole));
    let f = file::file_open("sha256.goose");
    assert(f != 0);
    var h: u32[8] = [0; 8];
    assert(sha256::stream(f, h));
    file::file_close(f);
    assert(h == sha256::digest(whole));
}
