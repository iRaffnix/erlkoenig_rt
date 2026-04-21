/*
 * Copyright 2026 Erlkoenig Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * fuzz_spawn_parser.c — libFuzzer target for ek_parse_cmd_spawn.
 *
 * Feeds random bytes to the SPAWN command parser and asserts:
 *   - never crashes
 *   - never aborts (UBSan catches integer overflow, alignment, etc.)
 *   - never accesses memory outside the input buffer (ASan)
 *   - always returns a clean 0 or negative errno
 *
 * The parser is imported via ek_protocol.h and linked against
 * src/ek_protocol.c — the SAME code that ships in erlkoenig_rt.
 *
 * Build:
 *   clang -fsanitize=fuzzer,address,undefined -g \
 *     -I include -D_GNU_SOURCE \
 *     test/fuzz/fuzz_spawn_parser.c src/ek_protocol.c \
 *     -o fuzz_spawn
 *
 * Run:
 *   ./fuzz_spawn -max_len=65536 -timeout=5 test/fuzz/corpus/spawn
 */

#include <stddef.h>
#include <stdint.h>

#include "ek_protocol.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct erlkoenig_spawn_opts opts;
	int ret = ek_parse_cmd_spawn(data, size, &opts);

	/*
	 * Sanity: return value must be 0 or a POSIX negative errno.
	 * A positive value would violate the ABI contract — trap so
	 * the fuzzer notices.
	 */
	if (ret > 0)
		__builtin_trap();

	/* opts may be partially written on error; we don't rely on it. */
	(void)opts;
	return 0;
}
