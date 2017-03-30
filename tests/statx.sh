#!/bin/sh

# Check decoding of stat family syscalls.

. "${srcdir=.}/init.sh"
run_strace_match_diff -v -P "$STRACE_TEST_SAMPLE" -P /dev/full -a32
