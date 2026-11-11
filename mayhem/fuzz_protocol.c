// Fuzzes nfqws2's L7 payload dissectors (HTTP, TLS, DNS, WireGuard, DHT, STUN, ...) and the
// position-marker resolver on one raw payload.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "protocol.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	// exact-size heap copies, so ASan sees any read past the end of the payload
	uint8_t *buf = malloc(size ? size : 1);
	char *str = malloc(size + 1);
	if (!buf || !str) abort();
	memcpy(buf, data, size);
	memcpy(str, data, size);
	str[size] = 0;

	char host[256], hdr[256];

	IsHttp(buf, size);
	HttpExtractHost(buf, size, host, sizeof(host));
	HttpExtractHeader(buf, size, "\nHost:", hdr, sizeof(hdr));
	if (IsHttpReply(buf, size))
	{
		HttpReplyCode(buf);
		HttpReplyLooksLikeDPIRedirect(buf, size, "example.com");
	}
	{
		uint8_t *p;
		uint8_t *cp = malloc(size ? size : 1);
		if (!cp) abort();
		memcpy(cp, data, size);
		HttpFindHost(&p, cp, size);
		free(cp);
	}

	for (int partial = 0; partial < 2; partial++)
	{
		IsTLSClientHello(buf, size, partial);
		IsTLSServerHello(buf, size, partial);
		TLSHelloExtractHost(buf, size, host, sizeof(host), partial);
		const uint8_t *ext; size_t extlen;
		TLSFindExt(buf, size, 0, &ext, &extlen, partial);
		// the *Handshake variants take a hello that callers pre-check for 6 bytes (desync.c: `if (sz < 6) return;`)
		if (size >= 6)
		{
			TLSHelloExtractHostFromHandshake(buf, size, host, sizeof(host), partial);
			TLSFindExtInHandshake(buf, size, 0x10, &ext, &extlen, partial);
		}
	}
	if (size >= 5)
	{
		TLSRecordLen(buf);
		IsTLSRecordFull(buf, size);
		TLSRecordDataLen(buf);
	}
	if (size >= 6) { TLSHandshakeLen(buf); IsTLSHandshakeFull(buf, size); }
	{
		size_t off;
		TLSFindExtLen(buf, size, &off);
		TLSFindExtLenOffsetInHandshake(buf, size, &off);
	}

	IsXMPPStream(buf, size); IsXMPPStartTLS(buf, size); IsXMPPProceedTLS(buf, size); IsXMPPFeatures(buf, size);
	IsDNSQuery(buf, size); IsDNSResponse(buf, size);
	IsWireguardHandshakeInitiation(buf, size); IsWireguardHandshakeResponse(buf, size);
	IsWireguardHandshakeCookie(buf, size); IsWireguardKeepalive(buf, size); IsWireguardData(buf, size);
	IsDht(buf, size); IsDiscordIpDiscoveryRequest(buf, size); IsStunMessage(buf, size); IsMTProto(buf, size);
	IsDTLS(buf, size); IsDTLSClientHello(buf, size); IsDTLSServerHello(buf, size);
	IsBTHandshake(buf, size); IsUTP_BTHandshake(buf, size);

	for (int m = 0; m < PM_LAST; m++)
		for (int l7p = 0; l7p < L7P_LAST; l7p++)
		{
			struct proto_pos sp = { .marker = m, .pos = (int16_t)(size ? data[size - 1] : 0) - 128 };
			ResolvePos(buf, size, l7p, &sp);
		}
	{
		struct proto_pos mk[8];
		int mct = 8;
		if (posmarker_list_parse(str, mk, &mct) && mct)
		{
			ssize_t pos[8]; int pct;
			ResolveMultiPos(buf, size, L7P_UNKNOWN, mk, mct, pos, &pct);
			ResolveMultiPos(buf, size, L7P_HTTP_REQ, mk, mct, pos, &pct);
			ResolveMultiPos(buf, size, L7P_TLS_CLIENT_HELLO, mk, mct, pos, &pct);
		}
	}

	free(buf);
	free(str);
	return 0;
}
