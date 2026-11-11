// Fuzzes the fake-TLS modifier behind nfqws2's tls_mod(): input = "<mod list>\n<fake ClientHello>".
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "protocol.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const uint8_t *nl = memchr(data, '\n', size);
	size_t mlen = nl ? (size_t)(nl - data) : size;
	size_t rest = nl ? size - mlen - 1 : 0;
	const uint8_t *tls = nl ? nl + 1 : data + size;

	char *modlist = malloc(mlen + 1);
	if (!modlist) abort();
	memcpy(modlist, data, mlen);
	modlist[mlen] = 0;

	struct fake_tls_mod mod;
	if (!TLSMod_parse_list(modlist, &mod) || !mod.mod)
	{
		free(modlist);
		return -1;
	}

	// same buffer contract as lua.c luacall_tls_mod(): original length + room for an SNI + 4
	size_t newlen = rest, maxlen = rest + sizeof(mod.sni) + 4;
	uint8_t *newtls = malloc(maxlen);
	// the payload to take the SNI/session id from is the same hello
	uint8_t *payload = malloc(rest ? rest : 1);
	if (!newtls || !payload) abort();
	memcpy(newtls, tls, rest);
	memcpy(payload, tls, rest);
	TLSMod(&mod, payload, rest, newtls, &newlen, maxlen);

	free(payload);
	free(newtls);
	free(modlist);
	return 0;
}
