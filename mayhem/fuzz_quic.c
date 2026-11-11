// Fuzzes the QUIC Initial path: header parsing, initial-secret derivation, header-protection removal,
// AES-GCM decryption (nfq2/crypto) and CRYPTO frame defragmentation.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "protocol.h"

#define MAX_REASM 16384

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t *buf = malloc(size ? size : 1);
	if (!buf) abort();
	memcpy(buf, data, size);

	IsQUICInitial(buf, size);
	QUICIsLongHeader(buf, size);
	quic_cid_t cid;
	QUICExtractDCID(buf, size, &cid);
	uint32_t ver = QUICExtractVersion(buf, size);
	QUICDraftVersion(ver);

	uint8_t clean[MAX_REASM], defrag[MAX_REASM];
	size_t clean_len = sizeof(clean);
	if (QUICDecryptInitial(buf, size, clean, &clean_len))
	{
		size_t defrag_len = sizeof(defrag), hello_off, hello_len;
		bool full;
		if (QUICDefragCrypto(clean, clean_len, defrag, &defrag_len, &full))
			IsQUICCryptoHello(defrag, defrag_len, &hello_off, &hello_len);
	}

	// the defragmenter also takes a plaintext frame stream directly
	size_t defrag_len = sizeof(defrag), hello_off, hello_len;
	bool full;
	if (QUICDefragCrypto(buf, size, defrag, &defrag_len, &full))
		IsQUICCryptoHello(defrag, defrag_len, &hello_off, &hello_len);

	free(buf);
	return 0;
}
