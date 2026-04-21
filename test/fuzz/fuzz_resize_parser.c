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
 * fuzz_resize_parser.c — libFuzzer target for ek_parse_cmd_resize.
 *
 * Build:
 *   clang -fsanitize=fuzzer,address,undefined -g \
 *     -I include -D_GNU_SOURCE \
 *     test/fuzz/fuzz_resize_parser.c src/ek_protocol.c \
 *     -o fuzz_resize
 */

#include <stddef.h>
#include <stdint.h>

#include "ek_protocol.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint16_t rows = 0;
	uint16_t cols = 0;
	int ret = ek_parse_cmd_resize(data, size, &rows, &cols);

	if (ret > 0)
		__builtin_trap();

	/* On success, both dimensions must be > 0. */
	if (ret == 0 && (rows == 0 || cols == 0))
		__builtin_trap();

	return 0;
}
