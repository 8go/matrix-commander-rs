#!/usr/bin/env bash
# echo "doing small cleanup of debug build"
ls -lh target/debug/incremental/matrix_commander_rs-* target/debug/matrix-commander-rs* 2> /dev/null
rm -r -f target/debug/incremental/matrix_commander_rs-* target/debug/matrix-commander-rs*
