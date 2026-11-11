// Shared start-up for the harnesses that run nfqws2's embedded Lua: set up the global `params`
// the way nfqws.c main() does (minus option parsing and the NFQUEUE loop) and call lua_init().
#pragma once
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "params.h"
#include "lua.h"
#include "filter.h"
#include "crypto/aes.h"

struct func_list *parse_lua_call(char *opt, struct func_list_head *flist);

// Optional extra @file init script, loaded between zapret-lib.lua and the dispatcher.
static const char *fuzz_lua_extra_script;

static void fuzz_lua_env_init(const char *dispatcher_code, const char *desync_call)
{
	const char *dir = getenv("ZAPRET_LUA_DIR");
	char path[512];

	snprintf(params.verstr, sizeof(params.verstr), "mayhem fuzz harness");
	aes_init_keygen_tables();
	init_params(&params);
	params.intercept = false;
	params.debug = false;
	params.droproot = false;
	params.lua_gc = 0;

	struct desync_profile_list *dpl = dp_list_add(&params.desync_profiles);
	if (!dpl) abort();
	dpl->dp.n = 1;
	dpl->dp.filter_ipv4 = dpl->dp.filter_ipv6 = true;
	if (desync_call)
	{
		char *call = strdup(desync_call);
		struct func_list *f = parse_lua_call(call, &dpl->dp.lua_desync);
		free(call);
		if (!f) abort();
		f->payload_type = 0;
		f->range_in = PACKET_RANGE_ALWAYS;
		f->range_out = PACKET_RANGE_ALWAYS;
	}

	ConntrackPoolInit(&params.conntrack, 10, params.ctrack_t_syn, params.ctrack_t_est, params.ctrack_t_fin, params.ctrack_t_udp);

	snprintf(path, sizeof(path), "@%s/zapret-lib.lua", dir && *dir ? dir : "/mayhem/lua");
	if (!strlist_add_tail(&params.lua_init_scripts, path)) abort();
	if (fuzz_lua_extra_script && !strlist_add_tail(&params.lua_init_scripts, fuzz_lua_extra_script)) abort();
	if (!strlist_add_tail(&params.lua_init_scripts, dispatcher_code)) abort();
	if (!lua_init())
	{
		fprintf(stderr, "lua_init failed\n");
		abort();
	}
}
