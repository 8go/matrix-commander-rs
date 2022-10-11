[![crates.io - Version](
https://img.shields.io/crates/v/matrix-commander
)](https://crates.io/crates/matrix-commander)
[![crates.io - Downloads](
https://img.shields.io/crates/d/matrix-commander
)](https://crates.io/crates/matrix-commander)

<p>
<img
src="https://raw.githubusercontent.com/8go/matrix-commander-rs/master/logos/matrix-commander-rs.svg"
alt="MC logo" height="150">

# matrix-commander-rs
simple but convenient CLI-based Matrix client app for sending and receiving

# Help create this Rust program!

This project is currently only a vision. The Python package matrix-commander
exists. See [matrix-commander](https://github.com/8go/matrix-commander/).
The vision is to have a compatible program in Rust. I cannot do it myself,
but I can coordinate and merge your pull requests.
This project depends on you. The project will only advance if you provide
the code. Have a look at the repo
[matrix-commander-rs](https://github.com/8go/matrix-commander-rs/).
Please help! :pray: Please contribute code to make this vision a reality,
and to one day have a functional
[matrix-commander](https://crates.io/crates/matrix-commander) crate.
Safe!

:heart: :clap: :pray:

# What you can do

- Give a :star: on Github. The more stars on Github, the more people will
  see the project. Do it now, thanks. :clap:
- Talk about it to your friends, post it in chatrooms, Hacker News, etc.
  This will give exposure and help find people willing to provide code,
  contributions, and PRs.
- Write code yourself. :rocket:

# Ideas

- Make it compatible with the Python version of `matrix-commander`, i.e.
  same config file, same CLI, etc. The user should be able to run
  the Python `matrix-commander` in the morning, and the Rust
  `matrix-commander` in the afternoon.
- Use similar modules as used in Python, e.g.
  [argparse](https://crates.io/crates/argparse).
- Use [matrix-rust-sdk](https://crates.io/crates/matrix-sdk).
- Use [ruma](https://crates.io/crates/ruma) if and where needed.
- Have a look at this small example
  [matrix-send-rs](https://crates.io/crates/matrix-sdk).

# Immediate action items
- re-create the `argparse` interface in Rust, making it as similar as
  possible to the Python `argparse` CLI code
- create Github workflow so that the crate on `crates.io` gets
  generated automatically on `pull request` or `push`.
- implement `login` via password (see some reference example code in
  [matrix-send-rs](https://crates.io/crates/matrix-sdk)) and SSO
- ...

# Contributors :clap:
- _Add your name here._
- Who will be the first?
