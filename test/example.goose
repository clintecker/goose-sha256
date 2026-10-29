// The README's example, run by make pkg-test so it keeps compiling.
import std;
import sha256 from "..";

fn main() {
    var s = sha256::start();
    sha256::add(s, "hello, ");
    sha256::add(s, "world");
    var out: u8[>..] = [];
    sha256::hex(out, sha256::finish(s));
    assert(out == "09ca7e4eaa6e8ae9c7d261167129184883644d07dfba7cbfbc4c8a2e08360d5b");
}
