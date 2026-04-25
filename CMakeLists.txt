cmake_minimum_required(VERSION 3.10)
project(erlkoenig_rt VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)  # _GNU_SOURCE for clone(), pivot_root(), etc.

add_executable(erlkoenig_rt
    src/erlkoenig_rt.c
    src/ek_protocol.c
    src/erlkoenig_ns.c
    src/erlkoenig_netcfg.c
    src/erlkoenig_nft.c
    src/erlkoenig_devfilter.c
    src/erlkoenig_metrics.c
    src/erlkoenig_nodecert.c
    src/erlkoenig_cg.c
    src/erlkoenig_xdp.c
    src/erlkoenig_cloned.c
)

target_include_directories(erlkoenig_rt PRIVATE include)

# ---------------------------------------------------------------------------
# Compiler warnings -- the compiler is your mom, listen to her
# ---------------------------------------------------------------------------
target_compile_options(erlkoenig_rt PRIVATE
    -Wall
    -Wextra
    -Werror
    -Wshadow
    -Wstrict-prototypes
    -Wold-style-definition
    -Wmissing-prototypes
    -Wmissing-declarations
    -Wno-unused-parameter
    -Wformat=2
    -Wformat-security
    -Wconversion
    -Wsign-conversion
    -Wnull-dereference
    -Wdouble-promotion
    -Wwrite-strings
    -Wcast-align
    -Wredundant-decls
    -Wnested-externs
    -Wswitch-enum
    -Wundef
    -Wvla
)

# GCC-specific warnings (clang ignores unknown -W flags with a warning)
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    target_compile_options(erlkoenig_rt PRIVATE
        -Wlogical-op
        -Wduplicated-cond
        -Wduplicated-branches
        -Wjump-misses-init
        -Wstringop-overflow=4
        -Wformat-truncation=2
        -Wformat-overflow=2
    )
    # GCC static analyzer (GCC 10+)
    if(CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 10)
        option(ERLKOENIG_ANALYZER "Enable GCC -fanalyzer" OFF)
        if(ERLKOENIG_ANALYZER)
            target_compile_options(erlkoenig_rt PRIVATE -fanalyzer)
        endif()
    endif()
endif()

# ---------------------------------------------------------------------------
# Hardening -- defense in depth
# ---------------------------------------------------------------------------
target_compile_definitions(erlkoenig_rt PRIVATE
    _GNU_SOURCE
    $<$<NOT:$<CONFIG:Debug>>:_FORTIFY_SOURCE=2>
)

# ---------------------------------------------------------------------------
# Linking: static musl (default) or dynamic glibc (sanitizers only)
# ---------------------------------------------------------------------------
option(ERLKOENIG_SANITIZE "Enable ASan + UBSan (forces dynamic glibc build)" OFF)

# Common hardening for both modes
target_compile_options(erlkoenig_rt PRIVATE
    -fstack-protector-strong
    -fno-strict-aliasing
    $<$<NOT:$<CONFIG:Debug>>:-O2>
    $<$<CONFIG:Debug>:-O0 -g>
)
target_link_options(erlkoenig_rt PRIVATE
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
)

if(ERLKOENIG_SANITIZE)
    # Sanitizers need dynamic glibc — cannot use musl
    message(STATUS "Sanitizer build: dynamic glibc (ASan + UBSan)")
    target_compile_options(erlkoenig_rt PRIVATE
        -fPIE
        -fsanitize=address,undefined
        -fno-omit-frame-pointer
    )
    target_link_options(erlkoenig_rt PRIVATE
        -pie
        -fsanitize=address,undefined
    )
else()
    # Default: static musl — zero runtime dependencies
    message(STATUS "Static musl build: zero runtime dependencies")
    set(MUSL_KERNEL_HEADERS "/usr/include" CACHE PATH
        "Path to linux kernel headers (linux/, asm-generic/)")
    set(MUSL_ARCH_HEADERS "/usr/include/x86_64-linux-gnu" CACHE PATH
        "Path to arch-specific kernel headers (asm/)")

    target_compile_options(erlkoenig_rt PRIVATE
        -static
        "SHELL:-idirafter ${MUSL_KERNEL_HEADERS}"
        "SHELL:-idirafter ${MUSL_ARCH_HEADERS}"
    )
    target_link_options(erlkoenig_rt PRIVATE -static)
endif()

# ---------------------------------------------------------------------------
# ek_rtctl (CLI control tool — minimal, same static build)
# ---------------------------------------------------------------------------
add_executable(ek_rtctl src/ek_rtctl.c)
target_include_directories(ek_rtctl PRIVATE include)
target_compile_options(ek_rtctl PRIVATE
    -Wall -Wextra -Werror -Wno-unused-parameter
    $<$<NOT:$<CONFIG:Debug>>:-O2>
)
target_compile_definitions(ek_rtctl PRIVATE _GNU_SOURCE)
if(NOT ERLKOENIG_SANITIZE)
    target_compile_options(ek_rtctl PRIVATE
        -static
        "SHELL:-idirafter ${MUSL_KERNEL_HEADERS}"
        "SHELL:-idirafter ${MUSL_ARCH_HEADERS}"
    )
    target_link_options(ek_rtctl PRIVATE -static)
else()
    target_compile_options(ek_rtctl PRIVATE
        -fsanitize=address,undefined
        -fno-omit-frame-pointer
    )
    target_link_options(ek_rtctl PRIVATE
        -fsanitize=address,undefined
    )
endif()

# ---------------------------------------------------------------------------
# Gateway demo (FaaS HTTP gateway — container per request)
# ---------------------------------------------------------------------------
option(ERLKOENIG_BUILD_GATEWAY "Build the FaaS gateway demo" ON)

if(ERLKOENIG_BUILD_GATEWAY)
    add_executable(gateway
        demo/gateway.c
        src/erlkoenig_netcfg.c
    )

    target_include_directories(gateway PRIVATE include)
    target_compile_options(gateway PRIVATE
        -Wall -Wextra -Werror -Wno-unused-parameter
        -Wformat=2 -Wformat-security
        $<$<NOT:$<CONFIG:Debug>>:-O2>
        $<$<CONFIG:Debug>:-O0 -g>
        -fstack-protector-strong
    )
    target_compile_definitions(gateway PRIVATE _GNU_SOURCE)
    target_link_libraries(gateway pthread)
    target_link_options(gateway PRIVATE
        -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
    )

    if(NOT ERLKOENIG_SANITIZE)
        target_compile_options(gateway PRIVATE
            -static
            "SHELL:-idirafter ${MUSL_KERNEL_HEADERS}"
            "SHELL:-idirafter ${MUSL_ARCH_HEADERS}"
        )
        target_link_options(gateway PRIVATE -static)
    else()
        target_compile_options(gateway PRIVATE
            -fPIE
            -fsanitize=address,undefined
            -fno-omit-frame-pointer
        )
        target_link_options(gateway PRIVATE
            -pie
            -fsanitize=address,undefined
        )
    endif()

    set_target_properties(gateway PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    )
endif()

# ---------------------------------------------------------------------------
# Test binaries (statically linked container workloads)
# ---------------------------------------------------------------------------
option(ERLKOENIG_BUILD_TESTBIN "Build test binaries for integration tests" ON)

if(ERLKOENIG_BUILD_TESTBIN)
    set(TESTBIN_SOURCES
        sleeper echo_server crasher mem_eater disk_writer cpu_burner stdout_flood
        hello_output syscall_fork syscall_mount syscall_write_rootfs
        stdin_echo proc_check landlock_check
    )

    foreach(tb ${TESTBIN_SOURCES})
        add_executable(erlkoenig_tb_${tb} testbin/${tb}.c)
        set_target_properties(erlkoenig_tb_${tb} PROPERTIES
            OUTPUT_NAME test-erlkoenig-${tb}
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/testbin"
        )
        target_compile_options(erlkoenig_tb_${tb} PRIVATE -Wall -Wextra)
        target_link_options(erlkoenig_tb_${tb} PRIVATE -static)

        install(TARGETS erlkoenig_tb_${tb}
            RUNTIME DESTINATION lib/erlkoenig/testbin
            COMPONENT testbin)
    endforeach()
endif()

# ---------------------------------------------------------------------------
# C-Runtime Unit Tests (libcheck framework)
# ---------------------------------------------------------------------------
option(ERLKOENIG_BUILD_TESTS "Build C-runtime unit tests (needs libcheck)" OFF)

if(ERLKOENIG_BUILD_TESTS)
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(CHECK check)
    endif()

    if(NOT CHECK_FOUND)
        find_path(CHECK_INCLUDE_DIRS check.h)
        find_library(CHECK_LINK_LIBS check)
        find_library(SUBUNIT_LIB subunit)
        if(CHECK_INCLUDE_DIRS AND CHECK_LINK_LIBS)
            set(CHECK_FOUND TRUE)
            set(CHECK_LIBRARIES ${CHECK_LINK_LIBS})
            if(SUBUNIT_LIB)
                list(APPEND CHECK_LIBRARIES ${SUBUNIT_LIB})
            endif()
            list(APPEND CHECK_LIBRARIES m pthread rt)
        endif()
    endif()

    if(NOT CHECK_FOUND)
        message(FATAL_ERROR "libcheck not found. Install: apt install check")
    endif()

    add_executable(test_container_setup
        test/test_container_setup.c
        src/erlkoenig_ns.c
        src/erlkoenig_netcfg.c
        src/erlkoenig_cg.c
    )

    target_include_directories(test_container_setup PRIVATE
        include
        ${CHECK_INCLUDE_DIRS}
    )

    target_compile_definitions(test_container_setup PRIVATE _GNU_SOURCE)
    target_compile_options(test_container_setup PRIVATE
        -Wall -Wextra -Wno-unused-parameter -g -O0
    )

    if(ERLKOENIG_SANITIZE)
        target_compile_options(test_container_setup PRIVATE
            -fsanitize=address,undefined
            -fno-omit-frame-pointer
        )
        target_link_options(test_container_setup PRIVATE
            -fsanitize=address,undefined
        )
    endif()

    target_link_libraries(test_container_setup ${CHECK_LIBRARIES})

    set_target_properties(test_container_setup PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/test"
    )
endif()

# ---------------------------------------------------------------------------
# LD_PRELOAD fault-injection shim (for fault-smoke / path-sweep)
# ---------------------------------------------------------------------------
# The shim is not instrumented with ASan itself — it wraps glibc syscall
# symbols via dlsym(RTLD_NEXT, …) and is LD_PRELOADed into an ASan-linked
# binary. Linking it with ASan would double-instrument the interposers.
option(ERLKOENIG_BUILD_FAULT_SHIM "Build LD_PRELOAD fault injector" OFF)

if(ERLKOENIG_BUILD_FAULT_SHIM)
    add_library(ek_fault_shim SHARED test/fault/ek_fault_shim.c)
    target_compile_definitions(ek_fault_shim PRIVATE _GNU_SOURCE)
    target_compile_options(ek_fault_shim PRIVATE
        -Wall -Wextra -g -O0 -fPIC
    )
    target_link_libraries(ek_fault_shim dl)
    set_target_properties(ek_fault_shim PROPERTIES
        PREFIX ""
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    )
endif()

# ---------------------------------------------------------------------------
# libFuzzer parser harnesses
# ---------------------------------------------------------------------------
# libFuzzer is Clang-only. The build-system integration lives in a
# SEPARATE build directory (build-fuzz) so the main sanitizer build
# (build-san) can use the default compiler. Enabling this option on a
# non-Clang compiler is a hard error — we don't want silent skips.
option(ERLKOENIG_BUILD_FUZZ "Build libFuzzer parser harnesses (Clang only)" OFF)

if(ERLKOENIG_BUILD_FUZZ)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR
            "ERLKOENIG_BUILD_FUZZ requires Clang (libFuzzer). "
            "Configure with -DCMAKE_C_COMPILER=clang.")
    endif()

    foreach(fz spawn kill net_setup resize)
        add_executable(fuzz_${fz}
            test/fuzz/fuzz_${fz}_parser.c
            src/ek_protocol.c
        )
        target_include_directories(fuzz_${fz} PRIVATE include)
        target_compile_definitions(fuzz_${fz} PRIVATE _GNU_SOURCE)
        target_compile_options(fuzz_${fz} PRIVATE
            -fsanitize=fuzzer,address,undefined
            -g -O1 -fno-omit-frame-pointer
        )
        target_link_options(fuzz_${fz} PRIVATE
            -fsanitize=fuzzer,address,undefined
        )
        set_target_properties(fuzz_${fz} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
        )
    endforeach()
endif()

# ---------------------------------------------------------------------------
# Boundary probes (defensive container-escape boundary verification)
# ---------------------------------------------------------------------------
# Each probe is a small statically-linked container workload that asserts
# a single boundary property (cap dropped, syscall denied, path masked,
# ...) and exits cleanly when the boundary holds. If a forbidden operation
# succeeds, the probe prints a FINDING line and exits non-zero.
#
# Probes are spawned by erlkoenig_rt under a representative hardening
# profile via the test/boundary/run_boundary_probes.sh harness.
option(ERLKOENIG_BUILD_BOUNDARY "Build defensive container-boundary probes" OFF)

if(ERLKOENIG_BUILD_BOUNDARY)
    file(GLOB BOUNDARY_PROBE_SOURCES
        RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/test/boundary"
        "${CMAKE_CURRENT_SOURCE_DIR}/test/boundary/probe_*.c"
    )

    foreach(probe_src ${BOUNDARY_PROBE_SOURCES})
        get_filename_component(probe_name "${probe_src}" NAME_WE)
        add_executable(${probe_name} test/boundary/${probe_src})
        target_include_directories(${probe_name} PRIVATE
            test/boundary
        )
        target_compile_definitions(${probe_name} PRIVATE _GNU_SOURCE)
        target_compile_options(${probe_name} PRIVATE
            -Wall -Wextra -O2 -g
        )
        target_link_options(${probe_name} PRIVATE -static)

        # Pick up linux/ uapi headers when building under musl-gcc, same
        # way the main runtime does (CMakeLists.txt:118–123).
        if(DEFINED MUSL_KERNEL_HEADERS)
            target_compile_options(${probe_name} PRIVATE
                "SHELL:-idirafter ${MUSL_KERNEL_HEADERS}"
                "SHELL:-idirafter ${MUSL_ARCH_HEADERS}"
            )
        endif()

        set_target_properties(${probe_name} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/test/boundary"
        )
    endforeach()

    list(LENGTH BOUNDARY_PROBE_SOURCES BOUNDARY_PROBE_COUNT)
    message(STATUS "Boundary probes enabled: ${BOUNDARY_PROBE_COUNT} probe(s)")

    # Single-connection probe driver — speaks the wire protocol
    # directly so the SPAWN→GO→WATCH lifecycle stays on one socket
    # connection. Mitigates the buffered-REPLY_EXITED race documented
    # in test/boundary/run_probe_one.c.
    add_executable(run_probe_one test/boundary/run_probe_one.c)
    target_include_directories(run_probe_one PRIVATE include)
    target_compile_definitions(run_probe_one PRIVATE _GNU_SOURCE)
    target_compile_options(run_probe_one PRIVATE -Wall -Wextra -O2 -g)
    target_link_options(run_probe_one PRIVATE -static)
    if(DEFINED MUSL_KERNEL_HEADERS)
        target_compile_options(run_probe_one PRIVATE
            "SHELL:-idirafter ${MUSL_KERNEL_HEADERS}"
            "SHELL:-idirafter ${MUSL_ARCH_HEADERS}"
        )
    endif()
    set_target_properties(run_probe_one PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/test/boundary"
    )
endif()

# ---------------------------------------------------------------------------
# Install targets
# ---------------------------------------------------------------------------
install(TARGETS erlkoenig_rt ek_rtctl
    RUNTIME DESTINATION lib/erlkoenig
    COMPONENT runtime)

file(WRITE "${CMAKE_BINARY_DIR}/VERSION" "${PROJECT_VERSION}\n")
install(FILES "${CMAKE_BINARY_DIR}/VERSION"
    DESTINATION lib/erlkoenig
    COMPONENT runtime)
