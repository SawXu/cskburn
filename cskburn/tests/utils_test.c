#include "utils.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(expr)                                  \
	do {                                             \
		if (!(expr)) {                                \
			fprintf(stderr, "check failed: %s\n", #expr); \
			return 1;                                  \
		}                                            \
	} while (0)

int
main(void)
{
	uint32_t addr;
	uint32_t size;
	const char *name;

	CHECK(scan_addr_size("0x1000:4096", &addr, &size));
	CHECK(addr == 0x1000 && size == 4096);
	CHECK(scan_addr_size("0XFFFFFFFF:0", &addr, &size));
	CHECK(addr == UINT32_MAX && size == 0);
	CHECK(!scan_addr_size("0x1000", &addr, &size));
	CHECK(!scan_addr_size(":4096", &addr, &size));
	CHECK(!scan_addr_size("0x1000:4096junk", &addr, &size));
	CHECK(!scan_addr_size("0x100000000:4096", &addr, &size));

	CHECK(scan_addr_size_name("0x2000:8192:dump.bin", &addr, &size, &name));
	CHECK(addr == 0x2000 && size == 8192 && strcmp(name, "dump.bin") == 0);
	CHECK(!scan_addr_size_name("0x2000:8192", &addr, &size, &name));
	CHECK(!scan_addr_size_name("0x2000::dump.bin", &addr, &size, &name));
	CHECK(!scan_addr_size_name("0x2000:8192:", &addr, &size, &name));

	return 0;
}
