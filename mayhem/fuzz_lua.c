// Fuzzes the C functions nfqws2 exposes to its Lua scripts (dissect/reconstruct, checksums, crypto, gzip,
// address conversion, position resolvers, fake-TLS modifier, ...) plus the Lua-side TLS/HTTP/URL parsers
// in lua/zapret-lib.lua. The first input byte selects what to call; the rest is split into arguments.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "lua_env.h"

static const char DISPATCHER[] =
"local MARKERS = {'host','endhost','sld','midsld','endsld','method','extlen','sniext','1','-1','host+2','midsld-1'}\n"
"local PAYLOADS = {'tls_client_hello','http_req','quic_initial','dns_query','unknown','wireguard_initiation'}\n"
"local FUNCS = {\n"
"  function(a) -- IP packet dissect/reconstruct round trip and checksum repair\n"
"    local d = dissect(a, #a%2==0)\n"
"    if d then\n"
"      local raw = reconstruct_dissect(d)\n"
"      if raw then dissect(raw) end\n"
"      reconstruct_dissect(d, {badsum=true})\n"
"      reconstruct_dissect(d, {keepsum=true, ip6_preserve_next=true})\n"
"      if d.ip then csum_ip4_fix(a:sub(1, 20+#(d.ip.options or ''))) end\n"
"    end\n"
"  end,\n"
"  function(a) -- single-header dissectors\n"
"    local h = dissect_iphdr(a); if h then reconstruct_iphdr(h) end\n"
"    h = dissect_ip6hdr(a); if h then reconstruct_ip6hdr(h, {ip6_last_proto=IPPROTO_UDP}) end\n"
"    h = dissect_tcphdr(a); if h then reconstruct_tcphdr(h) end\n"
"    h = dissect_udphdr(a); if h then reconstruct_udphdr(h) end\n"
"    h = dissect_icmphdr(a); if h then reconstruct_icmphdr(h) end\n"
"  end,\n"
"  function(a, x, y) -- checksum fixers take (ip header, l4 header, payload)\n"
"    local third = math.max(1, #a//3)\n"
"    local ip, l4, pl = a:sub(1,third), a:sub(third+1,2*third), a:sub(2*third+1)\n"
"    csum_tcp_fix(ip, l4, pl); csum_udp_fix(ip, l4, pl); csum_icmp_fix(ip, l4, pl)\n"
"  end,\n"
"  function(a) -- TLS record / ClientHello dissector\n"
"    for _, partial in ipairs({false, true}) do\n"
"      local t = tls_dissect(a, 1, partial)\n"
"      if t then tls_reconstruct(t) end\n"
"    end\n"
"  end,\n"
"  function(a) -- HTTP request / reply / URL parsers\n"
"    local r = http_dissect_req(a); if r then http_reconstruct_req(r) end\n"
"    http_dissect_reply(a)\n"
"    dissect_url(a)\n"
"    dissect_nld(a, 2)\n"
"  end,\n"
"  function(a, x) -- position resolvers: payload type and marker list are derived from the input\n"
"    local n = #a\n"
"    local pl = PAYLOADS[n % #PAYLOADS + 1]\n"
"    local m1 = MARKERS[(a:byte(1) or 0) % #MARKERS + 1]\n"
"    local m2 = MARKERS[(a:byte(n) or 0) % #MARKERS + 1]\n"
"    local ml = m1..','..m2\n"
"    resolve_pos(a, pl, m1, n%2==0)\n"
"    resolve_multi_pos(a, pl, ml, n%3==0)\n"
"    resolve_range(a, pl, ml, n%2==1, n%3==1)\n"
"  end,\n"
"  function(a, x, y) -- fake TLS modifier\n"
"    local opts = {'rnd','rndsni','dupsid','padencap','sni=example.org','rnd,dupsid','rndsni,padencap','sni=a.example,rnd'}\n"
"    local o = opts[(a:byte(1) or 0) % #opts + 1]\n"
"    tls_mod(x, o, y)\n"
"    tls_mod(a, o)\n"
"  end,\n"
"  function(a) -- streaming gzip: compress then decompress in two slices\n"
"    local half = #a//2\n"
"    local gz = gzip_init(nil, 1 + #a%9, 1 + #a%8)\n"
"    local z = gzip_deflate(gz, a:sub(1, half)) .. gzip_deflate(gz, a:sub(half+1)) .. gzip_deflate(gz, nil)\n"
"    gzip_end(gz)\n"
"    local g = gunzip_init()\n"
"    local out = gunzip_inflate(g, z)\n"
"    gunzip_end(g)\n"
"    assert(out == a, 'gzip roundtrip')\n"
"  end,\n"
"  function(a) -- gunzip of attacker bytes, split in two feeds\n"
"    local half = #a//2\n"
"    local g = gunzip_init()\n"
"    pcall(gunzip_inflate, g, a:sub(1, half))\n"
"    pcall(gunzip_inflate, g, a:sub(half+1))\n"
"    gunzip_end(g)\n"
"  end,\n"
"  function(a) -- block cipher and AEAD, key sizes 16/24/32\n"
"    local ks = ({16,24,32})[#a%3+1]\n"
"    local key, rest = a:sub(1,ks), a:sub(ks+1)\n"
"    local iv12, iv16 = rest:sub(1,12), rest:sub(1,16)\n"
"    local data = rest:sub(17)\n"
"    local e = aes(true, key, data); if e then aes(false, key, e) end\n"
"    aes(false, key, data)\n"
"    local ct, tag = aes_gcm(true, key, iv12, data, rest:sub(1,4))\n"
"    if ct then local pt = aes_gcm(false, key, iv12, ct, rest:sub(1,4)); assert(pt == data, 'gcm roundtrip') end\n"
"    aes_gcm(false, key, iv12, data, '')\n"
"    local c = aes_ctr(key, iv16, data); if c then assert(aes_ctr(key, iv16, c) == data, 'ctr roundtrip') end\n"
"  end,\n"
"  function(a) -- hashes and HKDF\n"
"    local third = math.max(1, #a//3)\n"
"    local salt, ikm, info = a:sub(1,third), a:sub(third+1,2*third), a:sub(2*third+1)\n"
"    for _, sha in ipairs({'sha256','sha224'}) do\n"
"      hash(sha, a)\n"
"      hkdf(sha, salt, ikm, info, 1 + #a%80)\n"
"    end\n"
"    bxor(salt, ikm); bor(salt, ikm); band(salt, ikm)\n"
"  end,\n"
"  function(a) -- address text <-> binary, hex\n"
"    local b = pton(a); if b then ntop(b) end\n"
"    ntop(a)\n"
"    parse_hex(a)\n"
"  end,\n"
"  function(a) -- integer pack/unpack at an offset taken from the input\n"
"    local pos = 1 + (a:byte(1) or 0) % 8\n"
"    u8(a,pos); u16(a,pos); u24(a,pos); u32(a,pos); u48(a,pos)\n"
"    local v = u32(a, pos) or 0\n"
"    bu8(v); bu16(v); bu24(v); bu32(v); bu48(v)\n"
"    swap16(v); swap24(v); swap32(v); swap48(v)\n"
"    bitnot8(v); bitnot16(v); bitnot24(v); bitnot32(v); bitnot48(v)\n"
"    local s = (a:byte(2) or 1) % 40\n"
"    bitlshift(v, s); bitrshift(v, s); bitand(v, v>>3); bitor(v, v>>3); bitxor(v, v>>3)\n"
"    bitget(v, s % 16, s % 16 + 8); bitset(v, s % 16, s % 16 + 8, 5)\n"
"    divint(v, 1 + s)\n"
"  end,\n"
"  function(a) -- calendar conversion\n"
"    local t = u32(a, 1) or 0\n"
"    local tm = gmtime(t); if tm then timegm(tm) end\n"
"    tm = localtime(t); if tm then timelocal(tm) end\n"
"  end,\n"
"}\n"
"function fuzz_one(s)\n"
"  local sel = (s:byte(1) or 0) % #FUNCS + 1\n"
"  local a = s:sub(2)\n"
"  local h = #a // 2\n"
"  FUNCS[sel](a, a:sub(1, h), a:sub(h+1))\n"
"end\n";

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	fuzz_lua_env_init(DISPATCHER, NULL);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	lua_State *L = params.L;
	int top = lua_gettop(L);

	lua_getglobal(L, "fuzz_one");
	lua_pushlstring(L, (const char *)data, size);
	// a Lua error is the script rejecting bad input (luaL_check*, assert); only native defects matter
	if (lua_pcall(L, 1, 0, 0) != LUA_OK)
	{
		const char *msg = lua_tostring(L, -1);
		// a failed round-trip assertion is a real finding, not a rejected input
		if (msg && strstr(msg, "roundtrip")) abort();
	}
	lua_settop(L, top);
	return 0;
}
