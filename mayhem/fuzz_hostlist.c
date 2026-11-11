// Fuzzes nfqws2's hostlist loader (plain text and gzip-compressed lists) and hostname matching.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "pools.h"
#include "hostlist.h"
#include "params.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const char *tmp = getenv("TMPDIR");
	char path[512];
	snprintf(path, sizeof(path), "%s/hostlist-XXXXXX", tmp && *tmp ? tmp : "/tmp");
	int fd = mkstemp(path);
	if (fd < 0) abort();
	size_t off = 0;
	while (off < size)
	{
		ssize_t w = write(fd, data + off, size - off);
		if (w <= 0) abort();
		off += w;
	}
	close(fd);

	hostlist_pool *pool = NULL;
	if (AppendHostList(&pool, path))
	{
		char host[256];
		size_t n = size < 255 ? size : 255;
		memcpy(host, data, n);
		host[n] = 0;
		for (char *p = host; *p; p++) if (*p == '\n') *p = 0;
		HostlistPoolGetStr(pool, host);
		NonEmptyHostlist(&pool);
	}
	HostlistPoolDestroy(&pool);
	unlink(path);
	return 0;
}
