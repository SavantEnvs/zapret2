// Plain (unsanitized) driver for test.sh: boots nfqws2's embedded Lua the way main() does and runs
// upstream's lua/zapret-tests.lua (C-function self tests) plus known-answer checks, printing one
// "TEST <name> PASS|FAIL" line per test. nfqws2 itself cannot run Lua as a non-root user
// (dropcaps() fails), hence this driver instead of `nfqws2 --lua-init=...`.
#include "lua_env.h"

static const char *TESTS =
"local names={'test_random','test_bop','test_aes','test_aes_gcm','test_aes_ctr','test_hkdf','test_hash',"
"'test_ub','test_bit','test_swap','test_ux','test_time','test_gzip','test_ipstr','test_dissect','test_csum'}\n"
"local fails=0\n"
"local function hx(s) return (string2hex(s):gsub(' ',''):lower()) end\n"
"local function report(n,ok,err)\n"
"  if not ok then fails=fails+1 end\n"
"  print('TEST '..n..' '..(ok and 'PASS' or ('FAIL '..tostring(err))))\n"
"end\n"
"for _,n in ipairs(names) do\n"
"  local f=_G[n]\n"
"  if f then local ok,err=pcall(f); report(n,ok,err) else report(n,false,'missing') end\n"
"end\n"
"report('kat_sha256_abc', hx(hash('sha256','abc'))=='ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')\n"
"report('kat_sha224_abc', hx(hash('sha224','abc'))=='23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7')\n"
"local ikm=string.rep('\\x0b',22)\n"
"local salt=''; for i=0,12 do salt=salt..string.char(i) end\n"
"local info=''; for i=0xf0,0xf9 do info=info..string.char(i) end\n"
"report('kat_hkdf_rfc5869_1', hx(hkdf('sha256',salt,ikm,info,42))=='3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865')\n"
"report('kat_bxor', hx(bxor('\\x0f\\xf0\\xaa','\\xff\\x0f\\x55'))=='f0ffff')\n"
"print('SUMMARY failed='..fails)\n";

int main(int argc, char *argv[]) // nfqws.h declares main() with this signature
{
	(void)argc; (void)argv;
	const char *dir = getenv("ZAPRET_LUA_DIR");
	static char path[512];
	snprintf(path, sizeof(path), "@%s/zapret-tests.lua", dir && *dir ? dir : "lua");
	fuzz_lua_extra_script = path;
	fuzz_lua_env_init(TESTS, NULL);
	return 0;
}
