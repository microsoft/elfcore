#!/bin/bash

# Test if we can successfully create a core dump of a process.

yes > /dev/null 2>&1 &
yes_pid=$!

if [[ $GITHUB_ACTIONS == "true" ]]; then
    # Run the binary directly as sudo is required in CI.
    cargo build -p elfcore-sample
    sudo ./target/debug/elfcore-sample -v $yes_pid dump.core
else
    cargo run -- -v $yes_pid dump.core
fi

dump_result="$?"
kill $yes_pid

if [[ $dump_result != 0 ]]; then
    echo "generating dump failed"
    exit $dump_result
fi

# Make sure the dump can be opened in gdb, even if there are no symbols.
gdb "$(which yes)" dump.core -q -ex "bt" -ex "q"
gdb_result="$?"

exit $gdb_result
