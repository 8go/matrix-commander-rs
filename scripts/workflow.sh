#!/bin/bash

echo "Welcome!"
echo "The script outlines the rough workflow"
echo ""
echo "You have written some code? Let's publish it."

git pull

echo "Update version number in Cargo.toml."

cargo fmt

# show files containing changes that were not yet committed into git
cargo package --list # a bit like `git status`

cargo build
cargo build --color always 2>&1 | less -r # if output is very long
# cargo build --examples
cargo test
cargo test --color always 2>&1 | less -r # if output is very long
cargo run
# cargo run --example example
# cargo run -- --version # pass some argument
cargo build --release
cargo run --release

# generate documentation
cargo doc
firefox target/doc/matrix_commander/index.html

git status
git commit -a
git push
git log -1 --pretty=%B # details of last commit
git status

cargo login # provide token
cargo publish --dry-run
cargo package --list # show files containing changes
cargo publish        # push to crates.io and doc.rs

cargo clean # rm ./target directory
