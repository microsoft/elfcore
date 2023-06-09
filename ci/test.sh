#!/bin/bash

# Test if we can successfully create a core dump of a process.

set -x

yes > /dev/null 2>&1 &
yes_pid=$!

if [[ $GITHUB_ACTIONS == "true" ]]; then
    # Run the binary directly as sudo is required in CI.
    cargo build -p elfcore-sample
    sudo ./target/elfcore-sample -v $yes_pid dump.core
else
    cargo run -- -v $yes_pid dump.core
fi

dump_result="$?"
kill $yes_pid

exit $dump_result
