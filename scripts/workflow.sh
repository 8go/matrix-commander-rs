#!/bin/bash

echo "Welcome!"
echo "The script outlines the rough workflow"
echo ""
echo "You have written some code? Let's publish it."

git pull

echo "Update version number in Cargo.toml."

rustfmt src/main.rs
cargo run
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
cargo package --list
cargo publish
