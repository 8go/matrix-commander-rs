#!/bin/bash

if [ -t 1 ]; then
    # echo terminal
    green="\e[1;37;1;42m"
    off="\e[0m"
    red="\e[1;37;1;41m"
else
    # echo "not a terminal", e.g. being piped out
    green=""
    off=""
    red=""
fi

# just in case PATH is not set correctly
PATH="./target/debug/:./target/release/:../target/debug/:../target/release/:.:./matrix_commander-rs:../matrix_commander-rs:$PATH"

# One may set similar values in the terminal before calling the script.
# export MCRS_OPTIONS="-d --room \!...some.room.id:matrix.example.org "

# getting some optional arguments
if [ "$MCRS_OPTIONS" != "" ]; then
    echo "Exellent. Variable MCRS_OPTIONS already set. " \
        "Using \"$MCRS_OPTIONS\" as additional options for testing."
else
    echo "If desired, set variable \"MCRS_OPTIONS\" for further options."
fi

echo "rustc version is: $(rustc -vV | xargs)"
echo "rustup version is: $(rustup --version)"
echo "cargo version is: $(cargo --version)"
echo "GITHUB_WORKFLOW = $GITHUB_WORKFLOW"
echo "GITHUB_REPOSITORY = $GITHUB_REPOSITORY"
echo "MCRS_OPTIONS = $MCRS_OPTIONS"

if [[ "$GITHUB_WORKFLOW" != "" ]]; then # if in Github Action Workflow
    echo "I am in Github Action Workflow $GITHUB_WORKFLOW."
fi

failures=0

function test1() {
    echo "=== Test 1: send a message ==="
    matrix-commander-rs -m foo $MCRS_OPTIONS
    res=$?
    if [ "$res" == "0" ]; then
        echo "SUCCESS"
    else
        echo >&2 "FAILURE"
        let failures++
    fi
}

function test2() {
    echo "=== Test 2: send two messages ==="
    matrix-commander-rs -m "foo" "bar" $MCRS_OPTIONS
    res=$?
    if [ "$res" == "0" ]; then
        echo "SUCCESS"
    else
        echo >&2 "FAILURE"
        let failures++
    fi
}
function test3() {
    echo "=== Test 3: send two messages ==="
    res=$(matrix-commander-rs -m "foo" "bar" -d $MCRS_OPTIONS 2>&1 >/dev/null | grep "message send successful" | wc -l)
    if [ "$res" == "2" ]; then
        echo "SUCCESS"
    else
        echo >&2 "FAILURE"
        let failures++
    fi
}

test1
test2
test3

failtext="failure"
if [ "$failures" != "1" ]; then
    failtext+="s" ## append an "s" to the end
fi
if [ "$failures" == "0" ]; then
    echo -e "${green}OK: Finished test series with $failures failures.${off}"
else
    echo -e "${red}ERROR: Finished test series with $failures $failtext.${off}"
fi

exit $failures
