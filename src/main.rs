//! The matrix-commander Crate
//!
//! Please help create the Rust version of matrix-commander.
//! Please consider providing Pull Requests.
//! Have a look at: <https://github.com/8go/matrix-commander-rs>
//!

// get the version number from Cargo.toml at compile time
const VERSION: Option<&str> = option_env!("CARGO_PKG_VERSION");
const PKG_NAME: Option<&str> = option_env!("CARGO_PKG_NAME");
const PKG_REPOSITORY: Option<&str> = option_env!("CARGO_PKG_REPOSITORY");
const PROG_WITHOUT_EXT: Option<&str> = PKG_NAME;

/// This function prints the version information
pub fn version() {
    println!("");
    println!(
        "  _|      _|      _|_|_|                     {}",
        PROG_WITHOUT_EXT.unwrap_or("matrix-commander")
    );
    print!("  _|_|  _|_|    _|             _~^~^~_       ");
    println!("a rusty vision of a Matrix CLI client");
    println!(
        "  _|  _|  _|    _|         \\) /  o o  \\ (/   version {}",
        VERSION.unwrap_or("unknown")
    );
    println!(
        "  _|      _|    _|           '_   -   _'     repo {}",
        PKG_REPOSITORY.unwrap_or("unknown")
    );
    print!("  _|      _|      _|_|_|     / '-----' \\     ");
    println!("please submit PRs to make the vision a reality");
    println!("");
}

/// This function asks the public for help
pub fn contribute() {
    println!("");
    println!(
        "This project is currently only a vision. The Python package {} ",
        PROG_WITHOUT_EXT.unwrap_or("matrix-commander")
    );
    println!("exists. The vision is to have a compatible program in Rust. I cannot do it myself, ");
    println!("but I can coordinate and merge your pull requests. Have a look at the repo ");
    println!(
        "{}. Please help! Please contribute ",
        PKG_REPOSITORY.unwrap_or("unknown")
    );
    println!("code to make this vision a reality, and to one day have a functional ");
    println!(
        "{} crate. Safe!",
        PROG_WITHOUT_EXT.unwrap_or("matrix-commander")
    );
}

/// Nothing is yet implemented. We need your code contributions!
fn main() {
    version();
    contribute();
}
