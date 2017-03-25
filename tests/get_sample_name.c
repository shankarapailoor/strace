#include "tests.h"
#include <stdlib.h>

const char *
get_sample_name(void)
{
	const char *name = getenv("STRACE_TEST_SAMPLE");

	if (!name || !*name)
		name = "test.sample";

	return name;
}
