#!/bin/bash

# Test if we can successfully create a core dump of a process.

set -x

yes > /dev/null 2>&1 &
yes_pid=$!

cargo run -- -v $yes_pid dump.core
dump_result="$?"
kill $yes_pid

exit $dump_result
