#!/usr/bin/env bash
PATH=".:./target/release/:./target/debug/:$PATH" &&
    matrix-commander-rs --usage >help.usage.txt
echo "help.usage.txt is $(wc -l help.usage.txt | cut -d ' ' -f1) lines long"
