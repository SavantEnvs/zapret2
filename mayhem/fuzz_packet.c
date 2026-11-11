// Fuzzes nfqws2's packet pipeline: dpi_desync_packet() on one raw IP packet — L3/L4 dissection, conntrack,
// TCP/UDP reassembly, protocol detection (TLS/HTTP/QUIC/...) and the call into a Lua desync function that
// exercises the dissect/reconstruct and payload parsers on whatever was detected.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "lua_env.h"
#include "desync.h"

// nfqws.c bounds every queued packet by this size (FUZZ_MAX_PACKET_SIZE / NFQ_MAX_RECV_SIZE)
#define MAX_PACKET (RECONSTRUCT_MAX_SIZE + 4096)

static const char DESYNC[] =
"function fuzz_desync(ctx, desync)\n"
"  local dis = desync.dis\n"
"  local pl = dis.payload\n"
"  if pl and #pl > 0 then\n"
"    if desync.l7payload == 'tls_client_hello' or desync.l7payload == 'tls_server_hello' then\n"
"      local t = tls_dissect(pl); if t then tls_reconstruct(t) end\n"
"    elseif desync.l7payload == 'http_req' then\n"
"      local r = http_dissect_req(pl); if r then http_reconstruct_req(r) end\n"
"    elseif desync.l7payload == 'http_reply' then\n"
"      http_dissect_reply(pl)\n"
"    end\n"
"    resolve_multi_pos(pl, desync.l7payload, 'host,sld,midsld,method,extlen,sniext,1,-1', true)\n"
"  end\n"
"  raw_packet(ctx)\n"
"  reconstruct_dissect(dis)\n"
"  return VERDICT_MODIFY\n"
"end\n";

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	fuzz_lua_env_init(DESYNC, "fuzz_desync");
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size > MAX_PACKET) return -1;

	// flows and cached hostnames/TTLs from earlier inputs must not influence this one
	ConntrackPoolDestroy(&params.conntrack);
	ipcacheDestroy(&params.ipcache);
	ConntrackPoolInit(&params.conntrack, 10, params.ctrack_t_syn, params.ctrack_t_est, params.ctrack_t_fin, params.ctrack_t_udp);

	uint8_t *pkt = malloc(size ? size : 1);
	uint8_t *mod = malloc(MAX_PACKET);
	if (!pkt || !mod) abort();
	memcpy(pkt, data, size);
	size_t modlen = MAX_PACKET;
	dpi_desync_packet(0, NULL, NULL, pkt, size, mod, &modlen);
	free(mod);
	free(pkt);
	return 0;
}
