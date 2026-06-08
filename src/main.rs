//! Welcome to the matrix-commander crate!
//!
//! Please help create the Rust version of matrix-commander.
//! Please consider providing Pull Requests.
//! Have a look at: <https://github.com/8go/matrix-commander-rs>
//!
//! `matrix-commander-rs` is a (partial initial) re-implementation
//! of the feature-rich `matrix-commander` (Python) program with
//! its repo at <https://github.com/8go/matrix-commander>.
//!
//! matrix-commander is a simple terminal-based CLI client of
//! Matrix <https://matrix.org>. It let's you login to your
//! Matrix account, verify your new devices, and send encrypted
//! (or not-encrypted) messages and files on the Matrix network.
//!
//! For building from source in Rust you require the
//! OpenSsl development library. Install it first, e.g. on
//! Fedora you would `sudo dnf install openssl-devel` or on
//! Ubuntu you would `sudo apt install libssl-dev`.
//!
//! Please help improve the code and add features  :pray:  :clap:
//!
//! Usage:
//! - matrix-commander-rs --login password # first time only
//! - matrix-commander-rs --bootstrap --verify manual-device # manual verification
//! - matrix-commander-rs --verify emoji # emoji verification
//! - matrix-commander-rs --message "Hello World" "Good Bye!"
//! - matrix-commander-rs --file test.txt
//! - or do many things at a time:
//! - matrix-commander-rs --login password --verify manual-device
//! - matrix-commander-rs --message Hi --file test.txt --devices --get-room-info
//!
//! For more information, see the README.md
//! <https://github.com/8go/matrix-commander-rs/blob/main/README.md>
//! file.

// #![allow(dead_code)] // crate-level allow  // Todo
// #![allow(unused_variables)] // Todo
// #![allow(unused_imports)] // Todo

// use mime::Mime;
// use tracing_subscriber;
use clap::{ColorChoice, CommandFactory, Parser, ValueEnum};
use colored::Colorize;
use directories::ProjectDirs;
use matrix_sdk::ruma::api::client::room::Visibility;
use regex::Regex;
use rpassword::read_password;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::env;
use std::fmt::{self, Debug};
use std::fs::{self, File};
use std::io::{self, stdin, stdout, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use thiserror::Error;
use tracing::{debug, enabled, error, info, warn, Level};
use tracing_subscriber::EnvFilter;
use update_informer::{registry, Check};
use url::Url;

use matrix_sdk::{
    // config::{RequestConfig, StoreConfig, SyncSettings},
    // instant::Duration,
    // room,
    ruma::{
        // api::client::search::search_events::v3::OwnedRoomIdOrUserId;
        OwnedDeviceId,
        OwnedMxcUri,
        // device_id, room_id, session_id, user_id, OwnedRoomId,  RoomId,
        OwnedUserId,
    },
    Client,
    SessionMeta,
};

/// import matrix-sdk Client related code of general kind: login, logout, verify, sync, etc
mod mclient;
use crate::mclient::{
    bootstrap, convert_to_full_alias_ids, convert_to_full_mxc_uris, convert_to_full_room_id,
    convert_to_full_room_ids, convert_to_full_user_ids, delete_devices_pre, devices, file,
    get_avatar, get_avatar_url, get_display_name, get_masterkey, get_profile, get_room_info,
    invited_rooms, joined_members, joined_rooms, left_rooms, login, logout, logout_local,
    media_delete, media_download, media_mxc_to_http, media_upload, message,
    replace_star_with_rooms, restore_credentials, restore_login, room_ban, room_create,
    room_enable_encryption, room_forget, room_get_state, room_get_visibility, room_invite,
    room_join, room_kick, room_leave, room_resolve_alias, room_unban, rooms, set_avatar,
    set_avatar_url, set_display_name, unset_avatar_url, verify,
};

// import matrix-sdk Client related code related to receiving messages and listening
mod listen;
use crate::listen::{listen_all, listen_forever, listen_once, listen_tail};

/// the version number from Cargo.toml at compile time
const VERSION_O: Option<&str> = option_env!("CARGO_PKG_VERSION");
/// fallback if static compile time value is None
const VERSION: &str = "unknown version";
/// the package name from Cargo.toml at compile time, usually matrix-commander
const PKG_NAME_O: Option<&str> = option_env!("CARGO_PKG_NAME");
/// fallback if static compile time value is None
const PKG_NAME: &str = "matrix-commander";
/// the name of binary program from Cargo.toml at compile time, usually matrix-commander-rs
const BIN_NAME_O: Option<&str> = option_env!("CARGO_BIN_NAME");
/// fallback if static compile time value is None
const BIN_NAME: &str = "matrix-commander-rs";
/// fallback if static compile time value is None
const BIN_NAME_UNDERSCORE: &str = "matrix_commander_rs";
/// he repo name from Cargo.toml at compile time,
/// e.g. string `https://github.com/8go/matrix-commander-rs/`
const PKG_REPOSITORY_O: Option<&str> = option_env!("CARGO_PKG_REPOSITORY");
/// fallback if static compile time value is None
const PKG_REPOSITORY: &str = "https://github.com/8go/matrix-commander-rs/";
/// default name for login credentials JSON file
const CREDENTIALS_FILE_DEFAULT: &str = "credentials.json";
/// default directory to be used by end-to-end encrypted protocol for persistent storage
const STORE_DIR_DEFAULT: &str = "store/";
/// default timeouts for waiting for the Matrix server, in seconds
const TIMEOUT_DEFAULT: u64 = 60;
/// URL for README.md file downloaded for --readme
const URL_README: &str = "https://raw.githubusercontent.com/8go/matrix-commander-rs/main/README.md";

/// The enumerator for Errors
#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Custom(&'static str),

    #[error("No valid home directory path")]
    NoHomeDirectory,

    #[error("Not logged in")]
    NotLoggedIn,

    #[error("Invalid Room")]
    InvalidRoom,

    #[error("Homeserver Not Set")]
    HomeserverNotSet,

    #[error("Invalid File")]
    InvalidFile,

    #[error("Login Failed")]
    LoginFailed,

    #[error("Verify Failed or Partially Failed")]
    VerifyFailed,

    #[error("Bootstrap Failed")]
    BootstrapFailed,

    #[error("Login Unnecessary")]
    LoginUnnecessary,

    #[error("Send Failed")]
    SendFailed,

    #[error("Listen Failed")]
    ListenFailed,

    #[error("Create Room Failed")]
    CreateRoomFailed,

    #[error("Leave Room Failed")]
    LeaveRoomFailed,

    #[error("Forget Room Failed")]
    ForgetRoomFailed,

    #[error("Invite Room Failed")]
    InviteRoomFailed,

    #[error("Join Room Failed")]
    JoinRoomFailed,

    #[error("Ban Room Failed")]
    BanRoomFailed,

    #[error("Unban Room Failed")]
    UnbanRoomFailed,

    #[error("Kick Room Failed")]
    KickRoomFailed,

    #[error("Resolve Room Alias Failed")]
    ResolveRoomAliasFailed,

    #[error("Enable Encryption Failed")]
    EnableEncryptionFailed,

    #[error("Room Get Visibility Failed")]
    RoomGetVisibilityFailed,

    #[error("Room Get State Failed")]
    RoomGetStateFailed,

    #[error("JoinedMembersFailed")]
    JoinedMembersFailed,

    #[error("Delete Device Failed")]
    DeleteDeviceFailed,

    #[error("Get Avatar Failed")]
    GetAvatarFailed,

    #[error("Set Avatar Failed")]
    SetAvatarFailed,

    #[error("Get Avatar URL Failed")]
    GetAvatarUrlFailed,

    #[error("Set Avatar URL Failed")]
    SetAvatarUrlFailed,

    #[error("Unset Avatar URL Failed")]
    UnsetAvatarUrlFailed,

    #[error("Get Displayname Failed")]
    GetDisplaynameFailed,

    #[error("Set Displayname Failed")]
    SetDisplaynameFailed,

    #[error("Get Profile Failed")]
    GetProfileFailed,

    #[error("Get Masterkey Failed")]
    GetMasterkeyFailed,

    #[error("Restoring Login Failed")]
    RestoreLoginFailed,

    #[error("Media Upload Failed")]
    MediaUploadFailed,

    #[error("Media Download Failed")]
    MediaDownloadFailed,

    #[error("Media Delete Failed")]
    MediaDeleteFailed,

    #[error("MXC TO HTTP Failed")]
    MediaMxcToHttpFailed,

    #[error("Invalid Client Connection")]
    InvalidClientConnection,

    #[error("Unknown CLI parameter")]
    UnknownCliParameter,

    #[error("Unsupported CLI parameter: {0}")]
    UnsupportedCliParameter(&'static str),

    #[error("Missing Room")]
    MissingRoom,

    #[error("Missing User")]
    MissingUser,

    #[error("Missing Password")]
    MissingPassword,

    #[error("Missing CLI parameter")]
    MissingCliParameter,

    #[error("Not Implemented Yet")]
    NotImplementedYet,

    #[error("No Credentials Found")]
    NoCredentialsFound,

    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[error(transparent)]
    Matrix(#[from] matrix_sdk::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Http(#[from] matrix_sdk::HttpError),
}

/// Function to create custom error messaages on the fly with static text
#[allow(dead_code)]
impl Error {
    pub(crate) fn custom<T>(message: &'static str) -> Result<T, Error> {
        Err(Error::Custom(message))
    }
}

/// Enumerator used for --login option
#[derive(Clone, Debug, Copy, PartialEq, Default, ValueEnum)]
enum Login {
    /// None: no login specified, don't login
    #[default]
    None,
    /// Password: login with password
    Password,
    /// AccessToken: login with access-token
    AccessToken,
    /// SSO: login with SSO, single-sign on
    Sso,
}

/// is_ functions for the enum
impl Login {
    pub fn is_password(&self) -> bool {
        self == &Self::Password
    }
    pub fn is_none(&self) -> bool {
        self == &Self::None
    }
}

/// Converting from String to Login for --login option
impl FromStr for Login {
    type Err = ();
    fn from_str(src: &str) -> Result<Login, ()> {
        return match src.to_lowercase().trim() {
            "none" => Ok(Login::None),
            "password" => Ok(Login::Password),
            "access_token" | "access-token" | "accesstoken" => Ok(Login::AccessToken),
            "sso" => Ok(Login::Sso),
            _ => Err(()),
        };
    }
}

/// Creates .to_string() for Login for --login option
impl fmt::Display for Login {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
        // or, alternatively:
        // fmt::Debug::fmt(self, f)
    }
}

/// Enumerator used for --sync option
#[derive(Clone, Debug, Copy, PartialEq, Default, ValueEnum)]
enum Sync {
    // None: only useful if one needs to know if option was used or not.
    // Sort of like an or instead of an Option<Sync>.
    // We do not need to know if user used the option or not,
    // we just need to know the value.
    // None,
    /// Turns syncing off for sending operations to improve performance
    Off,
    // partial,
    /// full: the default value
    #[default]
    Full,
}

/// is_ functions for the enum
impl Sync {
    pub fn is_off(&self) -> bool {
        self == &Self::Off
    }
    pub fn is_full(&self) -> bool {
        self == &Self::Full
    }
}

/// Converting from String to Sync for --sync option
impl FromStr for Sync {
    type Err = ();
    fn from_str(src: &str) -> Result<Sync, ()> {
        return match src.to_lowercase().trim() {
            "off" => Ok(Sync::Off),
            "full" => Ok(Sync::Full),
            _ => Err(()),
        };
    }
}

/// Creates .to_string() for Sync for --sync option
impl fmt::Display for Sync {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
        // or, alternatively:
        // fmt::Debug::fmt(self, f)
    }
}

/// Enumerator used for --version option
#[derive(Clone, Debug, Copy, PartialEq, Default, ValueEnum)]
enum Version {
    /// Check if there is a newer version available
    #[default]
    Check,
}

/// is_ functions for the enum
// impl Version {
//     pub fn is_check(&self) -> bool {
//         self == &Self::Check
//     }
// }

/// Converting from String to Version for --version option
impl FromStr for Version {
    type Err = ();
    fn from_str(src: &str) -> Result<Version, ()> {
        return match src.to_lowercase().trim() {
            "check" => Ok(Version::Check),
            _ => Err(()),
        };
    }
}

/// Creates .to_string() for Sync for --sync option
impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
        // or, alternatively:
        // fmt::Debug::fmt(self, f)
    }
}

/// Enumerator used for --verify option
#[derive(Clone, Debug, Copy, PartialEq, Default, ValueEnum)]
enum Verify {
    /// None: option not used, no verification done
    #[default]
    None,
    /// ManualDevice: manual device verification
    /// See also: https://docs.rs/matrix-sdk/0.7/matrix_sdk/encryption/identities/struct.Device.html#method.verify
    ManualDevice,
    /// ManualUser: manual user verification
    /// See also: https://docs.rs/matrix-sdk/0.7/matrix_sdk/encryption/identities/struct.UserIdentity.html#method.verify
    ManualUser,
    /// Emoji: verify via emojis as the recipient
    Emoji,
    /// Emoji: verify via emojis as the initiator
    EmojiReq,
}

/// is_ functions for the enum
impl Verify {
    pub fn is_none(&self) -> bool {
        self == &Self::None
    }
    pub fn is_manual_device(&self) -> bool {
        self == &Self::ManualDevice
    }
    pub fn is_manual_user(&self) -> bool {
        self == &Self::ManualUser
    }
    pub fn is_emoji(&self) -> bool {
        self == &Self::Emoji
    }
    pub fn is_emoji_req(&self) -> bool {
        self == &Self::EmojiReq
    }
}

/// Converting from String to Verify for --verify option
impl FromStr for Verify {
    type Err = ();
    fn from_str(src: &str) -> Result<Verify, ()> {
        return match src.to_lowercase().trim() {
            "none" => Ok(Verify::None),
            "manual-device" => Ok(Verify::ManualDevice),
            "manual-user" => Ok(Verify::ManualUser),
            "emoji" => Ok(Verify::Emoji),
            "emoji-req" => Ok(Verify::EmojiReq),
            _ => Err(()),
        };
    }
}

/// Creates .to_string() for Verify for --verify option
impl fmt::Display for Verify {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
        // or, alternatively:
        // fmt::Debug::fmt(self, f)
    }
}

/// Enumerator used for --logout option
#[derive(Clone, Debug, Copy, PartialEq, Default, ValueEnum)]
enum Logout {
    /// None: Log out nowhere, don't do anything, default
    #[default]
    None,
    /// Me: Log out from the currently used device
    Me,
    /// All: Log out from all devices of the user
    All,
}

/// is_ functions for the enum
impl Logout {
    pub fn is_none(&self) -> bool {
        self == &Self::None
    }
    pub fn is_me(&self) -> bool {
        self == &Self::Me
    }
    pub fn is_all(&self) -> bool {
        self == &Self::All
    }
}

/// Converting from String to Logout for --logout option
impl FromStr for Logout {
    type Err = ();
    fn from_str(src: &str) -> Result<Logout, ()> {
        return match src.to_lowercase().trim() {
            "none" => Ok(Logout::None),
            "me" => Ok(Logout::Me),
            "all" => Ok(Logout::All),
            _ => Err(()),
        };
    }
}

/// Creates .to_string() for Sync for --sync option
impl fmt::Display for Logout {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
        // or, alternatively:
        // fmt::Debug::fmt(self, f)
    }
}

/// Enumerator used for --listen (--tail) option
#[derive(Clone, Debug, Copy, PartialEq, Default, ValueEnum)]
enum Listen {
    // None: only useful if one needs to know if option was used or not.
    // Sort of like an or instead of an Option<Sync>.
    // We do not need to know if user used the option or not,
    // we just need to know the value.
    /// Never: Indicates to not listen, default
    #[default]
    Never,
    /// Once: Indicates to listen once in *all* rooms and then continue
    Once,
    /// Forever: Indicates to listen forever in *all* rooms, until process is killed manually.
    /// This is the only option that remains in the event loop.
    Forever,
    /// Tail: Indicates to get the last N messages from the specified room(s) and then continue
    Tail,
    /// All: Indicates to get *all* the messages from the specified room(s) and then continue
    All,
}

/// is_ functions for the enum
impl Listen {
    pub fn is_never(&self) -> bool {
        self == &Self::Never
    }
    pub fn is_once(&self) -> bool {
        self == &Self::Once
    }
    pub fn is_forever(&self) -> bool {
        self == &Self::Forever
    }
    pub fn is_tail(&self) -> bool {
        self == &Self::Tail
    }
    pub fn is_all(&self) -> bool {
        self == &Self::All
    }
}

/// Converting from String to Listen for --listen option
impl FromStr for Listen {
    type Err = ();
    fn from_str(src: &str) -> Result<Listen, ()> {
        return match src.to_lowercase().trim() {
            "never" => Ok(Listen::Never),
            "once" => Ok(Listen::Once),
            "forever" => Ok(Listen::Forever),
            "tail" => Ok(Listen::Tail),
            "all" => Ok(Listen::All),
            _ => Err(()),
        };
    }
}

/// Creates .to_string() for Listen for --listen option
impl fmt::Display for Listen {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
        // or, alternatively:
        // fmt::Debug::fmt(self, f)
    }
}

/// Enumerator used for --log-level option
#[derive(Clone, Debug, Copy, PartialEq, Default, ValueEnum)]
enum LogLevel {
    /// None: not set, default.
    #[default]
    None,
    /// Error: Indicates to print only errors
    Error,
    /// Warn: Indicates to print warnings and errors
    Warn,
    /// Info: Indicates to print info, warn and errors
    Info,
    /// Debug: Indicates to print debug and the rest
    Debug,
    /// Trace: Indicates to print everything
    Trace,
}

/// is_ functions for the enum
impl LogLevel {
    pub fn is_none(&self) -> bool {
        self == &Self::None
    }
    // pub fn is_error(&self) -> bool { self == &Self::Error }
}

// No longer used, as ValueEnum from clap crate provides similar function.
// /// Converting from String to LogLevel for --log-level option
// impl FromStr for LogLevel {
//     type Err = ();
//     fn from_str(src: &str) -> Result<LogLevel, ()> {
//         return match src.to_lowercase().trim() {
//             "none" => Ok(LogLevel::None),
//             "error" => Ok(LogLevel::Error),
//             "warn" => Ok(LogLevel::Warn),
//             "info" => Ok(LogLevel::Info),
//             "debug" => Ok(LogLevel::Debug),
//             "trace" => Ok(LogLevel::Trace),
//             _ => Err(()),
//         };
//     }
// }

/// Creates .to_string() for Listen for --listen option
impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
        // or, alternatively:
        // fmt::Debug::fmt(self, f)
    }
}

/// Enumerator used for --output option
#[derive(Clone, Debug, Copy, PartialEq, Default, ValueEnum)]
pub enum Output {
    // None: only useful if one needs to know if option was used or not.
    // Sort of like an or instead of an Option<Sync>.
    // We do not need to know if user used the option or not,
    // we just need to know the value.
    /// Text: Indicates to print human readable text, default
    #[default]
    Text,
    /// Json: Indicates to print output in Json format
    Json,
    /// Json Max: Indicates to print the maximum amount of output in Json format
    JsonMax,
    /// Json Spec: Indicates to print output in Json format, but only data that is according to Matrix Specifications
    JsonSpec,
}

/// is_ functions for the enum
impl Output {
    pub fn is_text(&self) -> bool {
        self == &Self::Text
    }
    // pub fn is_json_spec(&self) -> bool { self == &Self::JsonSpec }
}

/// Converting from String to Listen for --listen option
impl FromStr for Output {
    type Err = ();
    fn from_str(src: &str) -> Result<Output, ()> {
        return match src.to_lowercase().replace('-', "_").trim() {
            "text" => Ok(Output::Text),
            "json" => Ok(Output::Json),
            "jsonmax" | "json_max" => Ok(Output::JsonMax), // accept all 3: jsonmax, json-max, json_max
            "jsonspec" | "json_spec" => Ok(Output::JsonSpec),
            _ => Err(()),
        };
    }
}

/// Creates .to_string() for Listen for --listen option
impl fmt::Display for Output {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
        // or, alternatively:
        // fmt::Debug::fmt(self, f)
    }
}

// A public struct with private fields to keep the command line arguments from
// library `clap`.
/// Welcome to "matrix-commander-rs", a Matrix CLI client. ───
/// On the first run use --login to log in, to authenticate.
/// On the second run we suggest to use --verify to get verified.
/// Manual verification is built-in and can be used
/// to verify devices and users.
/// Or combine both --login and --verify in the first run.
/// On further runs "matrix-commander-rs" implements a simple Matrix CLI
/// client that can send messages or files, listen to messages,
/// operate on rooms, etc.  ───  ───
/// This project is currently only a vision.
/// The Python package "matrix-commander" exists.
/// The vision is to have a compatible program in Rust. I cannot
/// do it myself, but I can coordinate and merge your pull requests.
/// Have a look at the repo "https://github.com/8go/matrix-commander-rs/".
/// Please help! Please contribute code to make this vision a reality,
/// and to one day have a feature-rich "matrix-commander-rs" crate.
/// Safe!
#[derive(Clone, Debug, Parser)]
#[command(author, version,
    next_line_help = true,
    bin_name = get_prog_without_ext(),
    color = ColorChoice::Always,
    term_width = 79,
    after_help = "PS: Also have a look at scripts/matrix-commander-rs-tui.",
    disable_version_flag = true,
    disable_help_flag = true,
)]
pub struct Args {
    // This is an internal field used to store credentials.
    // The user is not setting this in the CLI.
    // This field is here to simplify argument passing.
    #[arg(skip)]
    creds: Option<Credentials>,

    /// Please contribute.
    #[arg(long, default_value_t = false)]
    contribute: bool,

    /// Print version number or check if a newer version exists on crates.io.
    /// Details::
    /// If used without an argument such as '--version' it will
    /// print the version number. If 'check' is added ('--version check')
    /// then the program connects to https://crates.io and gets the version
    /// number of latest stable release. There is no "calling home"
    /// on every run, only a "check crates.io" upon request. Your
    /// privacy is protected. New release is neither downloaded,
    /// nor installed. It just informs you.
    #[arg(short, long, value_name = "CHECK")]
    version: Option<Option<Version>>,

    /// Prints a very short help summary.
    /// Details:: See also --help, --manual and --readme.
    #[arg(long)]
    usage: bool,

    /// Prints short help displaying about one line per argument.
    /// Details:: See also --usage, --manual and --readme.
    #[arg(short, long)]
    help: bool,

    /// Prints long help.
    /// Details:: This is like a man page.
    /// See also --usage, --help and --readme.
    #[arg(long)]
    manual: bool,

    /// Prints README.md file, the documenation in Markdown.
    /// Details:: The README.md file will be downloaded from
    /// GitHub. It is a Markdown file and it is best viewed with a
    /// Markdown viewer.
    /// See also --usage, --help and --manual.
    #[arg(long)]
    readme: bool,

    /// Overwrite the default log level.
    /// Details::
    /// If not used, then the default
    /// log level set with environment variable 'RUST_LOG' will be used.
    /// If used, log level will be set to 'DEBUG' and debugging information
    /// will be printed.
    /// '-d' is a shortcut for '--log-level DEBUG'.
    /// If used once as in '-d' it will set and/or overwrite
    /// --log-level to '--log-level debug'.
    /// If used twice as in '-d -d' it will set and/or overwrite
    /// --log-level to '--log-level debug debug'.
    /// And third or futher occurrence of '-d' will be ignored.
    /// See also '--log-level'. '-d' takes precedence over '--log-level'.
    /// Additionally, have a look also at the option '--verbose'.
    #[arg(short, long,  action = clap::ArgAction::Count, default_value_t = 0u8, )]
    debug: u8,

    /// Set the log level by overwriting the default log level.
    /// Details::
    /// If not used, then the default
    /// log level set with environment variable 'RUST_LOG' will be used.
    /// If used with one value specified this value is assigned to the
    /// log level of matrix-commander-rs.
    /// If used with two values specified the first value is assigned to the
    /// log level of matrix-commander-rs. The second value is assigned to the
    /// lower level modules.
    /// More than two values should not be specified.
    /// --debug overwrites --log-level.
    /// See also '--debug' and '--verbose'.
    /// Alternatively you can use the RUST_LOG environment variable.
    /// An example use of RUST_LOG is to use neither --log-level nor --debug,
    /// and to set RUST_LOG="error,matrix_commander_rs=debug" which turns
    /// off debugging on all lower level modules and turns debugging on only
    /// for matrix-commander-rs.
    // Possible values are
    // '{trace}', '{debug}', '{info}', '{warn}', and '{error}'.
    #[arg(long, value_delimiter = ' ', num_args = 1..3, ignore_case = true, )]
    log_level: Option<Vec<LogLevel>>,

    /// Set the verbosity level.
    /// Details::
    /// If not used, then verbosity will be
    /// set to low. If used once, verbosity will be high.
    /// If used more than once, verbosity will be very high.
    /// Verbosity only affects the debug information.
    /// So, if '--debug' is not used then '--verbose' will be ignored.
    #[arg(long,  action = clap::ArgAction::Count, default_value_t = 0u8, )]
    verbose: u8,

    // Todo
    /// Disable encryption for a specific action.
    /// Details::
    /// By default encryption is turned on for all private rooms and DMs
    /// and turned off for all public rooms. E.g. Created DM or private room
    /// will have encryption enabled by default.
    /// To explicitly turn encryption off for a specific action use --plain.
    /// Currently --plain is supported by --room-create and --room-dm-create.
    /// See also --room-enable-encryption which sort of does the opposite for rooms.
    /// See also --visibility which allows setting the visibility of the room.
    #[arg(long)]
    plain: Option<bool>,

    /// Specify path to a file containing credentials.
    /// Details::
    /// At login (--login), information about homeserver, user, room
    /// id, etc. will be written to a credentials file. By
    /// default, this file is "credentials.json". On further
    /// runs the credentials file is read to permit logging
    /// into the correct Matrix account and sending messages
    /// to the preconfigured room. If this option is provided,
    /// the provided path to a file will be used as credentials
    /// file instead of the default one.
    /// E.g. ~/.local/share/matrix-commander-rs/credentials.json
    #[arg(short, long,
        value_name = "PATH_TO_FILE",
        value_parser = clap::value_parser!(PathBuf),
        default_value_os_t = get_credentials_default_path(),
        )]
    credentials: PathBuf,

    /// Specify a path to a directory to be used as "store" for encrypted
    /// messaging.
    /// Details::
    /// Since encryption is always enabled, a store is always
    /// needed. If this option is provided, the provided
    /// directory name will be used as persistent storage
    /// directory instead of the default one. Preferably, for
    /// multiple executions of this program use the same store
    /// for the same device. The store directory can be shared
    /// between multiple different devices and users.
    #[arg(short, long,
        value_name = "PATH_TO_DIRECTORY",
        // value_parser = clap::builder::ValueParser::path_buf(),
        value_parser = clap::value_parser!(PathBuf),
        default_value_os_t = get_store_default_path(),
        )]
    store: PathBuf,

    /// Login to and authenticate with the Matrix homeserver.
    /// Details::
    /// This requires exactly one argument, the login method.
    /// Currently two choices are offered: 'password' and 'SSO'.
    /// Provide one of these methods.
    /// If you have chosen 'password',
    /// you will authenticate through your account password. You can
    /// optionally provide these additional arguments:
    /// --homeserver to specify the Matrix homeserver,
    /// --user-login to specify the log in user id,
    /// --password to specify the password,
    /// --device to specify a device name,
    /// --room-default to specify a default room for sending/listening.
    /// If you have chosen 'SSO',
    /// you will authenticate through Single Sign-On. A web-browser will
    /// be started and you authenticate on the webpage. You can
    /// optionally provide these additional arguments:
    /// --homeserver to specify the Matrix homeserver,
    /// --user-login to specify the log in user id,
    /// --device to specify a device name,
    /// --room-default to specify a default room for sending/listening.
    /// See all the extra arguments for further explanations. -----
    /// SSO (Single Sign-On) starts a web
    /// browser and connects the user to a web page on the
    /// server for login. SSO will only work if the server
    /// supports it and if there is access to a browser. So, don't use SSO
    /// on headless homeservers where there is no
    /// browser installed or accessible.
    #[arg(long, value_enum,
        value_name = "LOGIN_METHOD",
        default_value_t = Login::default(), ignore_case = true, )]
    login: Login,

    /// Perform account verification.
    /// Details::
    /// By default, no
    /// verification is performed.
    /// Verification is currently offered via Manual-Device, Manual-User, Emoji and Emoji-Req.
    /// Do verification in this order: 1) bootstrap first with --bootstrap,
    /// 2) perform both manual verifications, and 3) perform emoji verification.
    /// --verify emoji has been tested against Element in Firefox browser and against
    /// Element app on Android phone. Both has been working successfully in Sept 2024.
    /// In Element web page it was important NOT to click the device in the device list,
    /// but to click the underscored link "Verify" just above the device list.
    /// In the Element on cell phone case, accept the emojis first on the cell phone.
    /// Manual verification is simpler but does less.
    /// Try: '--bootstrap --password mypassword --verify manual-device' or
    /// '--bootstrap --password mypassword --verify manual-user'.
    /// Manual only verifies devices or users one-directionally. See
    /// https://docs.rs/matrix-sdk/0.7/matrix_sdk/encryption/identities/struct.Device.html#method.verify
    /// and
    /// https://docs.rs/matrix-sdk/0.7/matrix_sdk/encryption/identities/struct.UserIdentity.html#method.verify
    /// for more info on Manual verification.
    /// manual-device can only verify its own devices, not other users' devices.
    /// manual-user can trust other users. So, with manual-user also use the --user option
    /// to specify one or multiple users. With manual-user first trust yourself, by
    /// setting --user to yourself, or omitting --user in which case it will default to itself.
    /// One should first do 'manual-device' and 'manual-user' verification and
    /// then 'emoji' or 'emoji-req' verification.
    /// Both 'emoji' as well as 'emoji-req' perform emoji verification.
    /// With 'emoji' we send a request to some other client to request verification from their device.
    /// With 'emoji-req' we wait for some other client to request verification from us.
    /// If verification is desired, run this program in the
    /// foreground (not as a service) and without a pipe.
    /// While verification is optional it is highly recommended, and it
    /// is recommended to be done right after (or together with) the
    /// --login action. Verification is always interactive, i.e. it
    /// requires keyboard input.
    /// Verification questions
    /// will be printed on stdout and the user has to respond
    /// via the keyboard to accept or reject verification.
    /// Once verification is complete, the program may be
    /// run as a service.
    /// Different Matrix clients (like Element app on cell phone,
    /// Element website in browser, other clients) have the
    /// "Verification" button hidden in different menus or GUI
    /// elements. Sometimes it is labelled "Not trusted", sometimes "Verify"
    /// or "Verify by emoji", sometimes "Verify With Other Device".
    /// Verification is best done as follows:
    /// Run 'matrix-commander-rs --verify emoji ...' and have the
    /// program waiting for inputs and for invitations.
    /// Find the appropriate "verify" button on your other client, click it,
    /// and thereby publish a "verification invitation". Once received by
    /// "matrix-commander-rs"
    /// it will print the emojis in the terminal.
    /// At this point both your client as well as "matrix-commander-rs" in the terminal
    /// show a set of emoji icons and names. Compare them visually.
    /// Confirm on both sides (Yes, They Match, Got it), finally click OK.
    /// You should see a green shield and also see that the
    /// matrix-commander-rs device is now green and verified.
    /// In the terminal you should see a text message indicating success.
    /// It has been tested with Element app on cell phone and Element webpage in
    /// browser. Verification is done one device at a time.
    /// 'emoji-req' is similar. You must specify a user with --user and
    /// a device with --device to specify to which device you want to send the
    /// verification request. On the other device you get a pop up and you
    /// must accept the verification request.
    /// 'emoji-req' currently seems to have problems, while it does work with Element
    /// web page in browser, 'emoji-req' does not seem to
    /// work with Element phone app.
    #[arg(long, value_enum,
        value_name = "VERIFICATION_METHOD",
        default_value_t = Verify::default(), ignore_case = true, )]
    verify: Verify,

    // Bootstrap cross signing.
    /// Details::
    /// By default, no
    /// bootstrapping is performed. Bootstrapping is useful for verification.
    /// --bootstrap creates cross signing keys.
    /// If you have trouble verifying with --verify manual-device or
    /// --verify manual-user, use --bootstrap before.
    /// Use --password to provide password. If --password is not given it will read
    /// password from command line (stdin). See also
    /// https://docs.rs/matrix-sdk/0.7.1/matrix_sdk/encryption/struct.CrossSigningStatus.html#fields.
    #[arg(long)]
    bootstrap: bool,

    /// Logout this or all devices from the Matrix homeserver.
    /// Details::
    /// This requires exactly one argument.
    /// Two choices are offered: 'me' and 'all'.
    /// Provide one of these choices.
    /// If you choose 'me', only the one device "matrix-commander-rs"
    /// is currently using will be logged out.
    /// If you choose 'all', all devices of the user used by
    /// "matrix-commander-rs" will be logged out.
    /// Using '--logout all' is equivalent to
    /// '--delete-device "*" --logout "me"' and requires a password
    ///  (see --delete-device).
    /// --logout not only logs the user out from the homeserver
    /// thereby invalidates the access token, it also removes both
    /// the 'credentials' file as well as the 'store' directory.
    /// After a --logout, one must perform a new
    /// --login to use "matrix-commander-rs" again.
    /// You can perfectly use "matrix-commander-rs"
    /// without ever logging out. --logout is a cleanup
    /// if you have decided not to use this (or all) device(s) ever again.
    #[arg(long, value_enum,
        value_name = "DEVICE",
        default_value_t = Logout::default(), ignore_case = true, )]
    logout: Logout,

    /// Specify a homeserver for use by certain actions.
    /// Details::
    /// It is an optional argument.
    /// By default --homeserver is ignored and not used.
    /// It is used by '--login' action.
    /// If not provided for --login the user will be queried via keyboard.
    #[arg(long)]
    homeserver: Option<Url>,

    /// Optional argument to specify the user for --login.
    /// Details::
    /// This gives the option to specify the user id for login.
    /// For '--login sso' the --user-login is not needed as user id can be
    /// obtained from server via SSO. For '--login password', if not
    /// provided it will be queried via keyboard. A full user id like
    /// '@john:example.com', a partial user name like '@john', and
    /// a short user name like 'john' can be given.
    /// --user-login is only used by --login and ignored by all other
    /// actions.
    #[arg(long)]
    user_login: Option<String>,

    /// Specify a password for use by certain actions.
    /// Details::
    /// It is an optional argument.
    /// By default --password is ignored and not used.
    /// It is used by '--login password' and '--delete-device'
    /// and --bootstrap actions.
    /// If not provided for --login, --delete-device or --bootstrap
    /// the user will be queried for the password via keyboard interactively.
    #[arg(long)]
    password: Option<String>,

    /// Specify a device name, for use by certain actions.
    /// Details::
    /// It is an optional argument.
    /// By default --device is ignored and not used.
    /// It is used by '--login' action.
    /// If not provided for --login the user will be queried via keyboard.
    /// If you want the default value specify ''.
    /// Multiple devices (with different device id) may have the same device
    /// name. In short, the same device name can be assigned to multiple
    /// different devices if desired
    /// Don't confuse this option with '--devices'.
    #[arg(long)]
    device: Option<String>,

    /// Optionally specify a room as the
    /// default room for future actions.
    /// Details::
    /// If not specified for --login, it
    /// will be queried via the keyboard. --login stores the specified room
    /// as default room in your credentials file. This option is only used
    /// in combination with --login. A default room is needed. Specify a
    /// valid room either with --room-default or provide it via keyboard.
    #[arg(long)]
    room_default: Option<String>,

    /// Print the list of devices.
    /// Details::
    /// All device of this
    /// account will be printed, one device per line.
    /// Don't confuse this option with --device.
    #[arg(long)]
    devices: bool,

    /// Set the timeout of the calls to the Matrix server.
    /// Details::
    /// By default they are set to 60 seconds.
    /// Specify the timeout in seconds. Use 0 for infinite timeout.
    #[arg(long, default_value_t = TIMEOUT_DEFAULT)]
    timeout: u64,

    /// Send one or more messages.
    /// Details::
    /// Message data must not be binary data, it
    /// must be text.
    // If no '-m' is used and no other conflicting
    // arguments are provided, and information is piped into the program,
    // then the piped data will be used as message.
    // Finally, if there are no operations at all in the arguments, then
    // a message will be read from stdin, i.e. from the keyboard.
    // This option can be used multiple times to send
    // multiple messages. If there is data piped
    // into this program, then first data from the
    // pipe is published, then messages from this
    // option are published. Messages will be sent last,
    // i.e. after objects like images, audio, files, events, etc.
    /// Input piped via stdin can additionally be specified with the
    /// special character '-'.
    /// If you want to feed a text message into the program
    /// via a pipe, via stdin, then specify the special
    /// character '-'.
    /// If your message is literally a single letter '-' then use an
    /// escaped '\-' or a quoted "\-".
    /// Depending on your shell, '-' might need to be escaped.
    /// If this is the case for your shell, use the escaped '\-'
    /// instead of '-' and '\\-' instead of '\-'.
    /// However, depending on which shell you are using and if you are
    /// quoting with double quotes or with single quotes, you may have
    /// to add backslashes to achieve the proper escape sequences.
    /// If you want to read the message from
    /// the keyboard use '-' and do not pipe anything into stdin, then
    /// a message will be requested and read from the keyboard.
    /// Keyboard input is limited to one line.
    /// The stdin indicator '-' may appear in any position,
    /// i.e. -m 'start' '-' 'end'
    /// will send 3 messages out of which the second one is read from stdin.
    /// The stdin indicator '-' may appear only once overall in all arguments.
    /// '-' reads everything that is in the pipe in one swoop and
    /// sends a single message.
    /// Similar to '-', another shortcut character
    /// is '_'. The special character '_' is used for
    /// streaming data via a pipe on stdin. With '_' the stdin
    /// pipe is read line-by-line and each line is treated as
    /// a separate message and sent right away. The program
    /// waits for pipe input until the pipe is closed. E.g.
    /// Imagine a tool that generates output sporadically
    /// 24x7. It can be piped, i.e. streamed, into matrix-
    /// commander, and matrix-commander stays active, sending
    /// all input instantly. If you want to send the literal
    /// letter '_' then escape it and send '\_'. '_' can be
    /// used only once. And either '-' or '_' can be used.
    #[arg(short, long, num_args(0..), )]
    message: Vec<String>,

    /// Specify the message format as Markdown.
    /// Details::
    /// There are 3 message formats for '--message'.
    /// Plain text, Markdown, and Code. By default, if no
    /// command line options are specified, 'plain text'
    /// will be used. Use '--markdown' or '--code' to set
    /// the format to Markdown or Code respectively.
    /// '--markdown' allows sending of text
    /// formatted in Markdown language. '--code' allows
    /// sending of text as a Code block.
    #[arg(long)]
    markdown: bool,

    /// Specify the message format as Code.
    /// Details::
    /// There are 3 message formats for '--message'.
    /// Plain text, Markdown, and Code. By default, if no
    /// command line options are specified, 'plain text'
    /// will be used. Use '--markdown' or '--code' to set
    /// the format to Markdown or Code respectively.
    /// '--markdown' allows sending of text
    /// formatted in Markdown language. '--code' allows
    /// sending of text as a Code block.
    #[arg(long)]
    code: bool,

    /// Send message as format "HTML"
    /// Details::
    /// If not specified, message will be sent
    /// as format "TEXT". E.g. that allows some text
    /// to be bold, etc. Only a subset of HTML tags are
    /// accepted by Matrix.
    #[arg(long)]
    html: bool,

    /// Optionally specify one or multiple rooms.
    /// Details::
    /// Specify rooms via room ids or
    /// room aliases. '--room' is used by
    /// various options like '--message', '--file', some
    /// variants of '--listen', '--delete-device', etc.
    /// The default room is provided
    /// in the credentials file (specified at --login with --room-default).
    /// If a room (or multiple ones)
    /// is (or are) provided in the --room arguments, then it
    /// (or they) will be used
    /// instead of the one from the credentials file.
    /// The user must have access to the specified room
    /// in order to send messages there or listen on the room.
    /// Messages cannot
    /// be sent to arbitrary rooms. When specifying the
    /// room id some shells require the exclamation mark
    /// to be escaped with a backslash.
    // As an alternative to specifying a room as destination,
    // one can specify a user as a destination with the '--user'
    // argument. See '--user' and the term 'DM (direct messaging)'
    // for details. Specifying a room is always faster and more
    // efficient than specifying a user.
    /// Not all listen operations
    /// allow setting a room. Read more under the --listen options
    /// and similar. Most actions also support room aliases or
    /// local canonical short aliases instead of
    /// room ids. Using a room id is
    /// always faster than using a room alias.
    #[arg(short, long, num_args(0..), )]
    room: Vec<String>,

    /// Send one or multiple files (e.g. PDF, DOC, MP4).
    /// Details::
    /// First files are sent,
    /// then text messages are sent.
    /// If you want to feed a file into "matrix-commander-rs"
    /// via a pipe, via stdin, then specify the special
    /// character '-' as stdin indicator.
    /// See description of '--message' to see how the stdin indicator
    /// '-' is handled.
    /// If you pipe a file into stdin, you can optionally use '--file-name' to
    /// attach a label and indirectly a MIME type to the piped data.
    /// E.g. if you pipe in a PNG file, you might want to specify additionally
    /// '--file-name image.png'. As such, the label 'image' will be given
    /// to the data and the MIME type 'png' will be attached to it.
    /// Furthermore, '-' can only be used once.
    #[arg(short, long, num_args(0..), )]
    file: Vec<String>,

    // Todo: change this Vec<String> to Vec<PathBuf> for --file
    /// Specify the message type as Notice.
    /// Details::
    /// There are 3 message types for '--message'.
    /// Text, Notice, and Emote. By default, if no
    /// command line options are specified, 'Text'
    /// will be used. Use '--notice' or '--emote' to set
    /// the type to Notice or Emote respectively.
    /// '--notice' allows sending of text
    /// as a notice. '--emote' allows
    /// sending of text as an emote.
    #[arg(long)]
    notice: bool,

    /// Specify the message type as Emote.
    /// Details::
    /// There are 3 message types for '--message'.
    /// Text, Notice, and Emote. By default, if no
    /// command line options are specified, 'Text'
    /// will be used. Use '--notice' or '--emote' to set
    /// the type to Notice or Emote respectively.
    /// '--notice' allows sending of text
    /// as a notice. '--emote' allows
    /// sending of text as an emote.
    #[arg(long)]
    emote: bool,

    /// Select synchronization choice.
    /// Details::
    /// This option decides on whether the program
    /// synchronizes the state with the server before a 'send' action.
    /// Currently two choices are offered: 'full' and 'off'.
    /// Provide one of these choices.
    /// The default is 'full'. If you want to use the default,
    /// then there is no need to use this option.
    /// If you have chosen 'full',
    /// the full state, all state events will be synchronized between
    /// this program and the server before a 'send'.
    /// If you have chosen 'off',
    /// synchronization will be skipped entirely before the 'send'
    /// which will improve performance.
    #[arg(long, value_enum,
        value_name = "SYNC_TYPE",
        default_value_t = Sync::default(), ignore_case = true, )]
    sync: Sync,

    /// Listen to messages.
    /// Details::
    /// The '--listen' option takes one argument. There are
    /// several choices: 'never', 'once', 'forever', 'tail',
    /// and 'all'. By default, --listen is set to 'never'. So,
    /// by default no listening will be done. Set it to
    /// 'forever' to listen for and print incoming messages to
    /// stdout. '--listen forever' will listen to all messages
    /// on all rooms forever. To stop listening 'forever', use
    /// Control-C on the keyboard or send a signal to the
    /// process or service.
    // The PID for signaling can be found
    // in a PID file in directory "/home/user/.run".
    /// '--listen once' will get all the messages from all rooms
    /// that are currently queued up. So, with 'once' the
    /// program will start, print waiting messages (if any)
    /// and then stop. The timeout for 'once' is set to 10
    /// seconds. So, be patient, it might take up to that
    /// amount of time. 'tail' reads and prints the last N
    /// messages from the specified rooms, then quits. The
    /// number N can be set with the '--tail' option. With
    /// 'tail' some messages read might be old, i.e. already
    /// read before, some might be new, i.e. never read
    /// before. It prints the messages and then the program
    /// stops. Messages are sorted, last-first. Look at '--tail'
    /// as that option is related to '--listen tail'. The option
    /// 'all' gets all messages available, old and new. Unlike
    /// 'once' and 'forever' that listen in ALL rooms, 'tail'
    /// and 'all' listen only to the room specified in the
    /// credentials file or the --room options.
    #[arg(short, long, value_enum,
        value_name = "LISTEN_TYPE",
        default_value_t = Listen::default(), ignore_case = true, )]
    listen: Listen,

    /// Get the last messages.
    /// Details::
    /// The '--tail' option reads and prints up to the last N
    /// messages from the specified rooms, then quits. It
    /// takes one argument, an integer, which we call N here.
    /// If there are fewer than N messages in a room, it reads
    /// and prints up to N messages. It gets the last N
    /// messages in reverse order. It print the newest message
    /// first, and the oldest message last. If '--listen-self'
    /// is not set it will print less than N messages in many
    /// cases because N messages are obtained, but some of
    /// them are discarded by default if they are from the
    /// user itself. Look at '--listen' as this option is
    /// related to '--tail'.
    #[arg(long, default_value_t = 0u64)]
    tail: u64,

    /// Get your own messages.
    /// Details::
    /// If set and listening, then program will listen to and
    /// print also the messages sent by its own user. By
    /// default messages from oneself are not printed.
    #[arg(short = 'y', long)]
    listen_self: bool,

    /// Print your user name.
    /// Details::
    /// Print the user id used by "matrix-commander-rs" (itself).
    /// One can get this information also by looking at the
    /// credentials file.
    #[arg(long)]
    whoami: bool,

    /// Specify the output format.
    /// Details::
    /// This option decides on how the output is presented.
    /// Currently offered choices are: 'text', 'json', 'json-max',
    /// and 'json-spec'. Provide one of these choices.
    /// The default is 'text'. If you want to use the default,
    /// then there is no need to use this option. If you have
    /// chosen 'text', the output will be formatted with the
    /// intention to be consumed by humans, i.e. readable
    /// text. If you have chosen 'json', the output will be
    /// formatted as JSON. The content of the JSON object
    /// matches the data provided by the matrix-nio SDK. In
    /// some occasions the output is enhanced by having a few
    /// extra data items added for convenience. In most cases
    /// the output will be processed by other programs rather
    /// than read by humans. Option 'json-max' is practically
    /// the same as 'json', but yet another additional field
    /// is added. The data item 'transport_response' which
    /// gives information on how the data was obtained and
    /// transported is also being added. For '--listen' a few
    /// more fields are added. In most cases the output will
    /// be processed by other programs rather than read by
    /// humans. Option 'json-spec' only prints information
    /// that adheres 1-to-1 to the Matrix Specification.
    /// Currently only the events on '--listen' and '--tail'
    /// provide data exactly as in the Matrix Specification.
    /// If no data is available that corresponds exactly with
    /// the Matrix Specification, no data will be printed. In
    /// short, currently '--json-spec' only provides outputs
    /// for '--listen' and '--tail'.
    // All other arguments like
    // '--get-room-info' will print no output.
    #[arg(short, long, value_enum,
        value_name = "OUTPUT_FORMAT",
        default_value_t = Output::default(), ignore_case = true, )]
    output: Output,

    /// Specify one or multiple file names for some actions.
    /// Details::
    /// This is an optional argument. Use this option in
    /// combination with options like '--file'.
    // or '--download'
    /// to specify
    /// one or multiple file names. Ignored if used by itself
    /// without an appropriate corresponding action.
    #[arg(long, num_args(0..), )]
    file_name: Vec<PathBuf>,

    /// Get room information.
    /// Details::
    /// Get the room information such as room display name,
    /// room alias, room creator, etc. for one or multiple
    /// specified rooms. The included room 'display name' is
    /// also referred to as 'room name' or incorrectly even as
    /// room title. If one or more rooms are given, the room
    /// information of these rooms will be fetched. If no
    /// room is specified, nothing will be done.
    /// If you want the room information for the
    /// preconfigured default room specify the shortcut '-'.
    /// Rooms can be given via room id (e.g.
    /// '\!SomeRoomId:matrix.example.com'), canonical (full)
    /// room alias (e.g. '#SomeRoomAlias:matrix.example.com'),
    /// or short alias (e.g. 'SomeRoomAlias' or
    /// '#SomeRoomAlias').
    /// As response room id, room display
    /// name, room canonical alias, room topic, room creator,
    /// and room encryption are printed. One line per room
    /// will be printed.
    /// Since either room id or room alias
    /// are accepted as input and both room id and room alias
    /// are given as output, one can hence use this option to
    /// map from room id to room alias as well as vice versa
    /// from room alias to room id.
    /// Do not confuse this option
    /// with the options '--get-display-name' and
    /// '--set-display-name', which get/set the user display name,
    /// not the room display name.
    /// The argument '--room-resolve-alias' can also be used
    /// to go the other direction, i.e. to find the room id
    /// given a room alias.
    #[arg(long, num_args(0..), value_name = "ROOM",
        alias = "room-get-info")]
    get_room_info: Vec<String>,

    /// Create one or multiple rooms.
    /// Details::
    /// One or multiple room
    /// aliases can be specified. For each alias specified a
    /// room will be created. For each created room one line
    /// with room id, alias, name and topic will be printed
    /// to stdout. If
    /// you are not interested in an alias, provide an empty
    /// string like ''. The alias provided must be in canonical
    /// local form, i.e. if you want a final full alias like
    /// '#SomeRoomAlias:matrix.example.com' you must provide
    /// the string 'SomeRoomAlias'. The user must be permitted
    /// to create rooms. Combine --room-create with --name and
    /// --topic to add names and topics to the room(s) to be
    /// created.
    /// If the output is in JSON format, then the values that
    /// are not set and hence have default values are not shown
    /// in the JSON output. E.g. if no topic is given, then
    /// there will be no topic field in the JSON output.
    /// Room aliases have to be unique.
    #[arg(long, num_args(0..), value_name = "LOCAL_ALIAS", )]
    room_create: Vec<String>,

    /// Set the visibility of the newly created room.
    /// Details::
    /// Default room visibility is 'private'.
    /// To create a public room, use
    /// '--room-create <room-name> --visibility public'.
    /// To create a private room, use
    /// '--room-create <room-name> --visibility private'.
    #[arg(long, value_enum,
        value_name = "VISIBILITY",
        default_value = Visibility::Private.as_str(), ignore_case = true, )]
    visibility: Visibility,

    /// Create one or multiple direct messaging (DM) rooms
    /// for given users.
    /// Details::
    /// One or multiple
    /// users can be specified. For each user specified a
    /// DM room will be created. For each created DM room one line
    /// with room id, alias, name and topic will be printed
    /// to stdout. The given user(s) will receive an invitation
    /// to join the newly created room.
    /// The user must be permitted
    /// to create rooms. Combine --room-dm-create with --alias,
    /// --name and
    /// --topic to add aliases, names and topics to the room(s) to be
    /// created.
    // If the output is in JSON format, then the values that
    // are not set and hence have default values are not shown
    // in the JSON output. E.g. if no topic is given, then
    // there will be no topic field in the JSON output.
    /// Room aliases in --alias have to be unique.
    #[arg(long, num_args(0..), value_name = "USER", )]
    room_dm_create: Vec<String>,

    /// Leave this room or these rooms.
    /// Details::
    /// One or multiple room
    /// aliases can be specified. The room (or multiple ones)
    /// provided in the arguments will be left.
    /// You can run both commands '--room-leave' and
    /// '--room-forget' at the same time
    #[arg(long, num_args(0..), value_name = "ROOM", )]
    room_leave: Vec<String>,

    /// Forget one or multiple rooms.
    /// Details::
    /// After leaving a room you should (most likely) forget
    /// the room. Forgetting a room removes the users' room
    /// history. One or multiple room aliases can be
    /// specified. The room (or multiple ones) provided in the
    /// arguments will be forgotten. If all users forget a
    /// room, the room can eventually be deleted on the
    /// server. You must leave a room first, before you can
    /// forget it
    /// You can run both commands '--room-leave' and
    /// '--room-forget' at the same time
    #[arg(long, num_args(0..), value_name = "ROOM", )]
    room_forget: Vec<String>,

    /// Invite one ore more users to join one or more rooms.
    /// Details::
    /// Specify the user(s) as arguments to --user. Specify
    /// the rooms as arguments to this option, i.e. as
    /// arguments to --room-invite. The user must have
    /// permissions to invite users.
    /// Use the shortcut '-' to specify the preconfigured
    /// default room of 'matrix-commander-rs' as room.
    #[arg(long, num_args(0..), value_name = "ROOM", )]
    room_invite: Vec<String>,

    /// Join one or multiple rooms.
    /// Details::
    /// One or multiple room
    /// aliases can be specified. The room (or multiple ones)
    /// provided in the arguments will be joined. The user
    /// must have permissions to join these rooms.
    /// Use the shortcut '-' to specify the preconfigured
    /// default room of 'matrix-commander-rs' as room.
    /// Note, no --user on this feature as the user is
    /// always the user of 'matrix-commander-rs'.
    #[arg(long, num_args(0..), value_name = "ROOM", )]
    room_join: Vec<String>,

    /// Ban one ore more users from one or more rooms.
    /// Details::
    /// Specify
    /// the user(s) as arguments to --user. Specify the rooms
    /// as arguments to this option, i.e. as arguments to
    /// --room-ban. The user must have permissions to ban
    /// users.
    /// Use the shortcut '-' to specify the preconfigured
    /// default room of 'matrix-commander-rs' as room.
    #[arg(long, num_args(0..), value_name = "ROOM", )]
    room_ban: Vec<String>,

    /// Unban one ore more users from one or more rooms.
    /// Details::
    /// Specify the user(s) as arguments to --user. Specify
    /// the rooms as arguments to this option, i.e. as
    /// arguments to --room-unban. The user must have
    /// permissions to unban users.
    /// Use the shortcut '-' to specify the preconfigured
    /// default room of 'matrix-commander-rs' as room.
    /// Note, this is currently not implemented in the
    /// matrix-sdk API. This feature will currently return
    /// an error.
    #[arg(long, num_args(0..), value_name = "ROOM", )]
    room_unban: Vec<String>,

    /// Kick one ore more users from one or more rooms.
    /// Details::
    /// Specify the user(s) as arguments to --user. Specify
    /// the rooms as arguments to this option, i.e. as
    /// arguments to --room-kick. The user must have
    /// permissions to kick users.
    /// Use the shortcut '-' to specify the preconfigured
    /// default room of 'matrix-commander-rs' as room.
    #[arg(long, num_args(0..), value_name = "ROOM", )]
    room_kick: Vec<String>,

    /// Resolves room aliases to room ids.
    /// Details::
    /// Resolves a room alias to the corresponding room id, or
    /// multiple room aliases to their corresponding room ids.
    /// Provide one or multiple room aliases. A room alias
    /// looks like this: '#someRoomAlias:matrix.example.org'.
    /// Short aliases like 'someRoomAlias' or '#someRoomAlias'
    /// are also accepted. In case of a short alias, it will
    /// be automatically prefixed with '#' and the homeserver
    /// from the default room of matrix-commander-rs (as found in
    /// credentials file) will be automatically appended.
    /// Resolving an alias that does not exist results in an
    /// error. For each room alias one line will be printed to
    /// stdout with the result. It also prints the list of
    /// servers that know about the alias(es).
    /// The argument '--get-room-info' can be used to go the
    /// other direction, i.e. to find the room aliases
    /// given a room id.
    #[arg(long, num_args(0..), value_name = "ALIAS", )]
    room_resolve_alias: Vec<String>,

    /// Enable encryption for one or multiple rooms.
    /// Details::
    /// Provide one or more room ids. For each room given
    /// encryption will be enabled. You must be member of the
    /// room in order to be able to enable encryption. Use
    /// shortcut '-' to enable encryption in the preconfigured
    /// default room. Enabling an already enabled room will
    /// do nothing and cause no error.
    #[arg(long, num_args(0..), value_name = "ROOM", )]
    room_enable_encryption: Vec<String>,

    /// Provide one or more aliases.
    /// Details::
    /// --alias is currently used in
    /// combination with --room-dm-create. It is ignored otherwise.
    /// Canonical short alias look like 'SomeRoomAlias'.
    /// Short aliases look like '#SomeRoomAlias'. And full aliases
    /// look like '#SomeRoomAlias:matrix.example.com'.
    /// If you are not interested in an alias, provide an empty
    /// string like ''. Remember that aliases must be unique. For
    /// --room-dm-create you must provide canonical short alias(es).
    #[arg(long, num_args(0..), value_name = "ALIAS", )]
    alias: Vec<String>,

    /// Specify one or multiple names.
    /// Details::
    /// This option is only
    /// meaningful in combination with option --room-create.
    /// This option --name specifies the names to be used with
    /// the command --room-create.
    #[arg(long, num_args(0..), )]
    name: Vec<String>,

    /// Specify one or multiple topics.
    /// Details::
    /// This option is only
    /// meaningful in combination with option --room-create.
    /// This option --topic specifies the topics to be used
    /// with the command --room-create.
    #[arg(long, num_args(0..), )]
    topic: Vec<String>,

    /// Print the list of past and current rooms.
    /// Details::
    /// All rooms that you
    /// are currently a member of (joined rooms), that you had been a
    /// member of in the past (left rooms), and rooms that you have
    /// been invited to (invited rooms) will be printed,
    /// one room per line. See also '--invited-rooms',
    /// '--joined-rooms', and '--left-rooms'.
    #[arg(long)]
    rooms: bool,

    /// Print the list of invited rooms.
    /// Details::
    /// All rooms that you are
    /// currently invited to will be printed, one room per line.
    #[arg(long)]
    invited_rooms: bool,

    /// Print the list of joined rooms.
    /// Details::
    /// All rooms that you are
    /// currently a member of will be printed, one room per line.
    #[arg(long)]
    joined_rooms: bool,

    /// Print the list of left rooms.
    /// Details::
    /// All rooms that you have
    /// left in the past will be printed, one room per line.
    #[arg(long)]
    left_rooms: bool,

    /// Get the visibility of one or more rooms.
    /// Details::
    /// Provide one
    /// or more room ids as arguments. If the shortcut '-' is
    /// used, then the default room of 'matrix-commander-rs' (as
    /// found in credentials file) will be used. The shortcut
    /// '*' represents all the rooms of the user of
    /// 'matrix-commander-rs'.
    /// For each room
    /// the visibility will be printed. Currently, this is
    /// either the string 'private' or 'public'. As response
    /// one line per room will be printed.
    #[arg(long, num_args(0..), alias = "get_room_visibility",
        value_name = "ROOM", )]
    room_get_visibility: Vec<String>,

    /// Get the state of one or more rooms.
    /// Details::
    /// Provide one or
    /// more room ids as arguments. If the shortcut '-' is
    /// used, then the default room of 'matrix-commander-rs' (as
    /// found in credentials file) will be used. The shortcut
    /// '*' represents all the rooms of the user of
    /// 'matrix-commander-rs'.
    /// For each room part of the
    /// state will be printed. The state is a long list of
    /// events. As
    /// response one line per room will be printed to stdout.
    /// The line can be very long as the list of events can be
    /// very large. To get output into a human readable form
    /// pipe output through sed and jq or use the JSON output.
    #[arg(long, num_args(0..), alias = "get_room_state",
        value_name = "ROOM", )]
    room_get_state: Vec<String>,

    /// Print the list of joined members for one or multiple
    /// rooms.
    /// Details::
    /// If you want to print the joined members of all
    /// rooms that you are member of, then use the special
    /// shortcut character '*'. If you want the members of
    /// the preconfigured default room, use shortcut '-'.
    #[arg(long, num_args(0..), value_name = "ROOM", )]
    joined_members: Vec<String>,

    /// Delete one or multiple devices.
    /// Details::
    /// By default devices
    /// belonging to itself, i.e. belonging to
    /// "matrix-commander-rs", will be deleted.
    /// If you want to delete the one device
    /// currently used for the connection, i.e. the device
    /// used by "matrix-commander-rs", then instead of the
    /// full device id you can just specify the shortcut 'me'
    /// such as '--delete-device me --password mypassword'.
    /// If you want to delete all devices of yourself, i.e.
    /// all devices owned by the user that
    /// "matrix-commander-rs" is using you can specify
    /// that with the shortcut '*'. Most shells require you
    /// to escape it or to quote it, ie. use
    /// '--delete-device "*" --password mypassword'.
    /// Removing your own device (e.g. 'me') or all devices
    /// (e.g. '*') will require you to manually remove your
    /// credentials file and store directory and to login
    /// anew in order to create a new device.
    /// If you are using
    /// '--delete-device me --password mypassword' consider
    /// using '--logout me' instead which is simpler
    /// (no password) and also automatically performs the
    /// removal of credentials and store. (See --logout.)
    /// If the devices belong to a different user, use the --user
    /// argument to specify the user, i.e. owner. Only exactly
    /// one user can be specified with the optional --user
    /// argument. Device deletion requires the user password.
    /// It must be specified with the --password argument. If
    /// the server uses only HTTP (and not HTTPS), then the
    /// password can be visible to attackers. Hence, if the
    /// server does not support HTTPS this operation is
    /// discouraged.
    /// If no --password is specified via the command line,
    /// the password is read from keyboard interactively.
    #[arg(long, num_args(0..),
        value_name = "DEVICE", )]
    delete_device: Vec<String>,

    /// Specify one or multiple users.
    /// Details::
    /// This option is
    /// meaningful in combination with
    /// a) room actions like
    /// --room-invite, --room-ban, --room-unban, etc. and
    // b)
    // send actions like -m, -i, -f, etc. c) some listen
    // actions --listen, as well as
    /// d) actions like
    /// --delete-device.
    /// In case of a) this option --user specifies the
    /// users to be used with room commands (like invite, ban,
    // etc.).
    // In case of b) the option --user can be used as
    // an alternative to specifying a room as destination for
    // text (-m), images (-i), etc. For send actions '--user'
    // is providing the functionality of 'DM (direct
    // messaging)'. For c) this option allows an alternative
    // to specifying a room as destination for some --listen
    // actions.
    /// For d) this gives the option to delete the
    /// device of a different user.
    // ----- What is a DM?
    // matrix-commander tries to find a room that contains
    // only the sender and the receiver, hence DM. These
    // rooms have nothing special other the fact that they
    // only have 2 members and them being the sender and
    // recipient respectively. If such a room is found, the
    // first one found will be used as destination. If no
    // such room is found, the send fails and the user should
    // do a --room-create and --room-invite first. If
    // multiple such rooms exist, one of them will be used
    // (arbitrarily). For sending and listening, specifying a
    // room directly is always faster and more efficient than
    // specifying a user. So, if you know the room, it is
    // preferred to use --room instead of --user. For b) and
    // c) --user can be specified in 3 ways: 1) full user id
    // as in '@john:example.org', 2) partial user id as in
    // '@john' when the user is on the same homeserver
    // (example.org will be automatically appended), or 3) a
    // display name as in 'john'. Be careful, when using
    // display names as they might not be unique, and you
    // could be sending to the wrong person. To see possible
    // display names use the --joined-members '*' option
    // which will show you the display names in the middle
    // column.
    /// If --user is not set, it will default to itself,
    /// i.e. the user of the "matrix-commander-rs" account.
    #[arg(short, long, num_args(0..), )]
    user: Vec<String>,

    /// Get your own avatar.
    /// Details::
    /// Get the avatar of itself, i.e. the
    /// 'matrix-commander-rs' user account. Specify a
    /// file optionally with path to store the image.
    /// E.g. --get-avatar "./avatar.png".
    #[arg(long, value_name = "FILE")]
    get_avatar: Option<PathBuf>,

    /// Set your own avatar.
    /// Details::
    /// Set, i.e. upload, an image to be used as avatar for
    /// 'matrix-commander-rs' user account. Specify a
    /// file optionally with path with the image. If the MIME
    /// type of the image cannot be determined, it will
    /// assume 'PNG' as default.
    /// E.g. --set-avatar "./avatar.jpg".
    /// It returns a line with the MRX URI of the new
    /// avatar.
    #[arg(long, alias = "upload-avatar", value_name = "FILE")]
    set_avatar: Option<PathBuf>,

    /// Get your own avatar URL.
    /// Details::
    /// Get the MXC URI of the avatar of itself, i.e. the
    /// 'matrix-commander-rs' user account.
    #[arg(long)]
    get_avatar_url: bool,

    /// Set your own avatar URL.
    /// Details::
    /// Set the avatar MXC URI of the URL to be used as avatar for
    /// the 'matrix-commander-rs' user account. Specify a
    /// MXC URI.
    /// E.g. --set-avatar-url "mxc://matrix.server.org/SomeStrangeStringOfYourMxcUri".
    #[arg(long, alias = "upload-avatar-url", value_name = "MAX_URI")]
    set_avatar_url: Option<OwnedMxcUri>,

    /// Remove your own avatar URL.
    /// Details::
    /// Remove the avatar MXC URI to be used as avatar for
    /// the 'matrix-commander-rs' user account. In other words, remove
    /// the avatar of the 'matrix-commander-rs' user.
    #[arg(long, alias = "remove-avatar")]
    unset_avatar_url: bool,

    /// Get your own display name.
    /// Details::
    /// Get the display name of itself, i.e. of the
    /// 'matrix-commander-rs' user account.
    #[arg(long)]
    get_display_name: bool,

    /// Set your own display name.
    /// Details::
    /// Set the display name of
    /// the 'matrix-commander-rs' user account. Specify a
    /// name.
    #[arg(long, value_name = "NAME")]
    set_display_name: Option<String>,

    /// Get your own profile.
    /// Details::
    /// Get the profile of itself, i.e. of the
    /// 'matrix-commander-rs' user account. This is
    /// getting both display name and avatar MXC URI in a call.
    #[arg(long)]
    get_profile: bool,

    /// Upload one or multiple files (e.g. PDF, DOC, MP4) to the
    /// homeserver content repository.
    /// Details::
    /// If you want to feed a file for upload into "matrix-commander-rs"
    /// via a pipe, via stdin, then specify the special
    /// character '-' as stdin indicator.
    /// See description of '--message' to see how the stdin indicator
    /// '-' is handled. Use --mime to optionally specify the MIME type
    /// of the file. If you give N arguments to --media-upload, you
    /// can give N arguments to --mime. See --mime.
    /// If you pipe a file into stdin, the MIME type cannot be guessed.
    /// It is hence more recommended that you specify a MIME type via
    /// '--mime' when using '-'.
    /// Furthermore, '-' can only be used once.
    /// Upon being stored in the homeserver's content repository, the
    /// data is assigned a Matrix MXC URI. For each file uploaded
    /// successfully, a
    /// single line with the MXC URI will be printed.
    /// The uploaded data will not by encrypted.
    /// If you want to upload encrypted data, encrypt the file before
    /// uploading it.
    // Use --plain to disable encryption for the upload.
    #[arg(long, alias = "upload", value_name = "FILE", num_args(0..), )]
    media_upload: Vec<PathBuf>,

    /// Download one or multiple files from the homeserver content
    /// repository.
    /// Details::
    /// You must provide one or multiple Matrix
    /// URIs (MXCs) which are strings like this
    /// 'mxc://example.com/SomeStrangeUriKey'.
    /// Alternatively,
    /// you can just provide the MXC id, i.e. the part after
    /// the last slash.
    /// If found they
    /// will be downloaded, decrypted, and stored in local
    /// files. If file names are specified with --file-name
    /// the downloads will be saved with these file names. If
    /// --file-name is not specified, then the file name
    /// 'mxc-<mxc-id>' will be used. If a file name in
    /// --file-name
    /// contains the placeholder __mxc_id__, it will be
    /// replaced with the mxc-id. If a file name is specified
    /// as empty string '' in --file-name, then also the name
    /// 'mxc-<mxc-id>' will be used. Be careful, existing
    /// files will be overwritten.
    // By default, the upload
    // was encrypted so a decryption dictionary must be
    // provided to decrypt the data. Specify one or multiple
    // decryption keys with --key-dict. If --key-dict is not
    // set, no decryption is attempted; and the data might
    // be stored in encrypted fashion, or might be plain-text
    // if the file was uploaded in plain text.
    // ....if the --upload skipped encryption with --plain. See
    // tests/test-upload.sh for an example.
    /// Do not confuse --media-download with --download-media.
    /// See --download-media.
    #[arg(long, alias = "download", value_name = "MXC_URI", num_args(0..), )]
    media_download: Vec<OwnedMxcUri>,

    /// Specify the Mime type of certain input files.
    /// Details::
    /// Specify '' if the Mime type should be guessed
    /// based on the filename. If input is from stdin
    /// (i.e. '-' and piped into 'matrix-commander-rs')
    /// then Mime type cannot be guessed. If not specified,
    /// and no filename available for guessing it will
    /// default to 'application/octet-stream'. Some example
    /// mime types are: 'image/jpeg', 'image/png', 'image/gif',
    /// 'text/plain', and 'application/pdf'. For a full
    /// list see 'https://docs.rs/mime/latest/mime/#constants'.
    // One cannot use Vec<Mime> as type because that prevents '' from being used.
    #[arg(long, value_name = "MIME_TYPE", num_args(0..), )]
    mime: Vec<String>,

    /// Delete one or multiple objects (e.g. files) from the
    /// content repository.
    /// Details::
    /// You must provide one or multiple
    /// Matrix URIs (MXC) which are strings like this
    /// 'mxc://example.com/SomeStrangeUriKey'. Alternatively,
    /// you can just provide the MXC id, i.e. the part after
    /// the last slash. If found they will be deleted from the
    /// server database. In order to delete objects one must
    /// have server admin permissions. Having only room admin
    /// permissions is not sufficient and it will fail. Read
    /// https://matrix-org.github.io/synapse/latest/usage/administration/admin_api/
    /// for learning how to set server
    /// admin permissions on the server.
    /// Thumbnails will currently not be deleted.
    /// Deleting something that does not exist will be ignored
    /// and will not cause an error.
    #[arg(long, alias = "delete-mxc", value_name = "MXC_URI", num_args(0..), )]
    media_delete: Vec<OwnedMxcUri>,

    /// Convert URIs to HTTP URLs.
    /// Details::
    /// Convert one or more matrix content URIs to the
    /// corresponding HTTP URLs. The MXC URIs to provide look
    /// something like this
    /// 'mxc://example.com/SomeStrangeUriKey'.
    /// Alternatively,
    /// you can just provide the MXC id, i.e. the part after
    /// the last slash.
    /// The syntax of the provided MXC URIs will be verified.
    /// The existence of content for the XMC URI will not be checked.
    // This works without a server or without being logged in.
    #[arg(long, alias = "mxc-to-http", value_name = "MXC_URI", num_args(0..), )]
    media_mxc_to_http: Vec<OwnedMxcUri>,

    /// Get your own master key.
    /// Details::
    /// Get the master key of itself, i.e. of the
    /// 'matrix-commander-rs' user account. Keep
    /// this key private and safe.
    #[arg(long)]
    get_masterkey: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self::new()
    }
}

impl Args {
    pub fn new() -> Args {
        Args {
            creds: None,
            usage: false,
            help: false,
            manual: false,
            readme: false,
            contribute: false,
            version: None,
            debug: 0u8,
            log_level: None,
            verbose: 0u8,
            plain: None,
            credentials: get_credentials_default_path(),
            store: get_store_default_path(),
            login: Login::None,
            bootstrap: false,
            verify: Verify::None,
            message: Vec::new(),
            logout: Logout::None,
            homeserver: None,
            user_login: None,
            password: None,
            device: None,
            room_default: None,
            devices: false,
            timeout: TIMEOUT_DEFAULT,
            markdown: false,
            code: false,
            html: false,
            room: Vec::new(),
            file: Vec::new(),
            notice: false,
            emote: false,
            sync: Sync::Full,
            listen: Listen::Never,
            tail: 0u64,
            listen_self: false,
            whoami: false,
            output: Output::Text,
            get_room_info: Vec::new(),
            file_name: Vec::new(),
            room_create: Vec::new(),
            visibility: Visibility::Private,
            room_dm_create: Vec::new(),
            room_leave: Vec::new(),
            room_forget: Vec::new(),
            room_invite: Vec::new(),
            room_join: Vec::new(),
            room_ban: Vec::new(),
            room_unban: Vec::new(),
            room_kick: Vec::new(),
            room_resolve_alias: Vec::new(),
            room_enable_encryption: Vec::new(),
            alias: Vec::new(),
            name: Vec::new(),
            topic: Vec::new(),
            rooms: false,
            invited_rooms: false,
            joined_rooms: false,
            left_rooms: false,
            room_get_visibility: Vec::new(),
            room_get_state: Vec::new(),
            joined_members: Vec::new(),
            delete_device: Vec::new(),
            user: Vec::new(),
            get_avatar: None,
            set_avatar: None,
            get_avatar_url: false,
            set_avatar_url: None,
            unset_avatar_url: false,
            get_display_name: false,
            set_display_name: None,
            get_profile: false,
            media_upload: Vec::new(),
            media_download: Vec::new(),
            media_delete: Vec::new(),
            media_mxc_to_http: Vec::new(),
            mime: Vec::new(),
            get_masterkey: false,
        }
    }
}

/// A struct for the credentials. These will be serialized into JSON
/// and written to the credentials.json file for permanent storage and
/// future access.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Credentials {
    homeserver: Url,
    user_id: OwnedUserId,
    access_token: String,
    device_id: OwnedDeviceId,
    // room_id (was room_default); renamed to room_id to make it compatible with Python version
    room_id: String,
    refresh_token: Option<String>,
}

impl AsRef<Credentials> for Credentials {
    fn as_ref(&self) -> &Self {
        self
    }
}

/// implementation of Credentials struct
impl Credentials {
    /// Default constructor
    fn new(
        homeserver: Url,
        user_id: OwnedUserId,
        access_token: String,
        device_id: OwnedDeviceId,
        room_id: String,
        refresh_token: Option<String>,
    ) -> Self {
        Self {
            homeserver,
            user_id,
            access_token,
            device_id,
            room_id,
            refresh_token,
        }
    }

    /// Constructor for Credentials
    fn load(path: &Path) -> Result<Credentials, Error> {
        let reader = File::open(path)?;
        Credentials::set_permissions(&reader)?;
        let credentials: Credentials = serde_json::from_reader(reader)?;
        let mut credentialsfiltered = credentials.clone();
        credentialsfiltered.access_token = "***".to_string();
        info!("loaded credentials are: {:?}", credentialsfiltered);
        Ok(credentials)
    }

    /// Writing the credentials to a file
    fn save(&self, path: &Path) -> Result<(), Error> {
        fs::create_dir_all(path.parent().ok_or(Error::NoHomeDirectory)?)?;
        let writer = File::create(path)?;
        serde_json::to_writer_pretty(&writer, self)?;
        Credentials::set_permissions(&writer)?;
        Ok(())
    }

    #[cfg(unix)]
    fn set_permissions(file: &File) -> Result<(), Error> {
        use std::os::unix::fs::PermissionsExt;
        let perms = file.metadata()?.permissions();
        // is the file world-readable? if so, reset the permissions to 600
        if perms.mode() & 0o4 == 0o4 {
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn set_permissions(file: &File) -> Result<(), Error> {
        Ok(())
    }
}

/// Implements From trait for Session
impl From<Credentials> for SessionMeta {
    fn from(creditials: Credentials) -> Self {
        Self {
            user_id: creditials.user_id,
            // 0.7 access_token: creditials.access_token,
            device_id: creditials.device_id,
            // no room_id (was default_room) in session
            // 0.7 refresh_token: creditials.refresh_token,
        }
    }

    //
    // From matrix-sdk doc
    // pub struct Session {
    //     pub access_token: String,
    //     pub refresh_token: Option<String>,
    //     pub user_id: OwnedUserId,
    //     pub device_id: OwnedDeviceId,
    // }
    //
    // A user session, containing an access token, an optional refresh token
    // and information about the associated user account.
    // Example
    //
    // use matrix_sdk_base::Session;
    // use ruma::{device_id, user_id};
    //
    // let session = Session {
    //     access_token: "My-Token".to_owned(),
    //     refresh_token: None,
    //     user_id: user_id!("@example:localhost").to_owned(),
    //     device_id: device_id!("MYDEVICEID").to_owned(),
    // };
    //
    // assert_eq!(session.device_id.as_str(), "MYDEVICEID");
}

// GlobalState is no longer used. I moved credentials into Args.creds
// in order to simplify.
// /// A public struct with a private fields to keep the global state
// #[derive(Clone)]
// pub struct GlobalState {
//     // self.log: logging.Logger = None  # logger object
//     ap: Args, // parsed arguments
//     // # to which logic (message, image, audio, file, event) is
//     // # stdin pipe assigned?
//     // self.stdin_use: str = "none"
//     // # 1) ssl None means default SSL context will be used.
//     // # 2) ssl False means SSL certificate validation will be skipped
//     // # 3) ssl a valid SSLContext means that the specified context will be
//     // #    used. This is useful to using local SSL certificate.
//     // self.ssl: Union[None, SSLContext, bool] = None
//     //client: AsyncClient,
//     // client: Option<String>,
//     //
//     // credentials_file_path was moved to Args.credentials
//     // credentials_file_path: PathBuf,
//     //
//     // store_dir_path was moved to Args.store
//     // store_dir_path: PathBuf,
//     //
//     // Session info and a bit more
//     credentials: Credentials,
//     //
//     // self.send_action = False  # argv contains send action
//     // self.listen_action = False  # argv contains listen action
//     // self.room_action = False  # argv contains room action
//     // self.set_action = False  # argv contains set action
//     // self.get_action = False  # argv contains get action
//     // self.setget_action = False  # argv contains set or get action
//     // self.err_count = 0  # how many errors have occurred so far
//     // self.warn_count = 0  # how many warnings have occurred so far
// }

// // /// implement the Default trait for GlobalState
// // impl Default for GlobalState {
// //     fn default() -> Self {
// //         Self::new()
// //     }
// // }

// /// Implementation of the GlobalState struct.
// impl GlobalState {
//     /// Default constructor of GlobalState
//     pub fn new(ap: Args, credentials: Credentials) -> GlobalState {
//         GlobalState { ap, credentials }
//     }
// }

/// Gets the *default* path (including file name) of the credentials file
/// The default path might not be the actual path as it can be overwritten with command line
/// options.
fn get_credentials_default_path() -> PathBuf {
    let dir = ProjectDirs::from_path(PathBuf::from(get_prog_without_ext())).unwrap();
    // fs::create_dir_all(dir.data_dir());
    let dp = dir.data_dir().join(CREDENTIALS_FILE_DEFAULT);
    debug!(
        "Data will be put into project directory {:?}.",
        dir.data_dir()
    );
    info!("Credentials file with access token is {}.", dp.display());
    dp
}

// Removed the Option, so it is always set by clap. Fn no longer needed.
// /// A credentials file is either specified with --credentials or the static default path is used
// /// On error return None.
// fn set_credentials(ap: &mut Args) {
//     debug!("set_credentials()");
//     let dcredentials = get_credentials_default_path();
//     if ap.credentials.is_empty() {
//         ap.credentials = Some(dcredentials); // since --credentials is empty, use default credentials path
//     }
// }

/// Gets the *actual* path (including file name) of the credentials file
/// The default path might not be the actual path as it can be overwritten with command line
/// options.
fn get_credentials_actual_path(ap: &Args) -> &PathBuf {
    &ap.credentials
}

/// Return true if credentials file exists, false otherwise
fn credentials_exist(ap: &Args) -> bool {
    let dp = get_credentials_default_path();
    let ap = get_credentials_actual_path(ap);
    debug!(
        "credentials_default_path = {:?}, credentials_actual_path = {:?}",
        dp, ap
    );
    let exists = ap.is_file();
    if exists {
        debug!("{:?} exists and is file. Not sure if readable though.", ap);
    } else {
        debug!("{:?} does not exist or is not a file.", ap);
    }
    exists
}

/// Gets the *default* path (terminating in a directory) of the store directory
/// The default path might not be the actual path as it can be overwritten with command line
/// options.
fn get_store_default_path() -> PathBuf {
    let dir = ProjectDirs::from_path(PathBuf::from(get_prog_without_ext())).unwrap();
    // fs::create_dir_all(dir.data_dir());
    let dp = dir.data_dir().join(STORE_DIR_DEFAULT);
    debug!("Default project directory is {:?}.", dir.data_dir());
    info!("Default store directory is {}.", dp.display());
    dp
}

// Removed the Option, so it is always set by clap. Fn no longer needed.
// /// A store is either specified with --store or the static default path is used
// /// On error return None.
// fn set_store(ap: &mut Args) {
//     debug!("set_store()");
//     let dstore = get_store_default_path();
//     if ap.store.is_empty() {
//         ap.store = Some(dstore); // since --store is empty, use default store path
//     }
// }

/// Gets the *actual* path (including file name) of the store directory
/// The default path might not be the actual path as it can be overwritten with command line
/// options.
/// set_store() must be called before this function is ever called.
fn get_store_actual_path(ap: &Args) -> &PathBuf {
    &ap.store
}

/// Return true if store dir exists, false otherwise
#[allow(dead_code)]
fn store_exist(ap: &Args) -> bool {
    let dp = get_store_default_path();
    let ap = get_store_actual_path(ap);
    debug!(
        "store_default_path = {:?}, store_actual_path = {:?}",
        dp, ap
    );
    let exists = ap.is_dir();
    if exists {
        debug!(
            "{:?} exists and is directory. Not sure if readable though.",
            ap
        );
    } else {
        debug!("{:?} does not exist or is not a directory.", ap);
    }
    exists
}

/// Gets version number, static if available, otherwise default.
fn get_version() -> &'static str {
    VERSION_O.unwrap_or(VERSION)
}

/// Gets Rust package name, static if available, otherwise default.
fn get_pkg_name() -> &'static str {
    PKG_NAME_O.unwrap_or(PKG_NAME)
}

/// Gets Rust binary name, static if available, otherwise default.
fn get_bin_name() -> &'static str {
    BIN_NAME_O.unwrap_or(BIN_NAME)
}

/// Gets Rust package repository, static if available, otherwise default.
fn get_pkg_repository() -> &'static str {
    PKG_REPOSITORY_O.unwrap_or(PKG_REPOSITORY)
}

/// Gets program name without extension.
fn get_prog_without_ext() -> &'static str {
    get_bin_name() // with -rs suffix
                   // get_pkg_name() // without -rs suffix
}

/// Prints the usage info
pub fn usage() {
    let help_str = Args::command().render_usage().to_string();
    println!("{}", &help_str);
    println!("Options:");
    // let cmd = Args::command();
    // // println!("{:?}", cmd);
    // // for arg in cmd.get_arguments() {
    // //         println!("{:?}",arg);
    // // }
    // // for arg in cmd.get_arguments() {
    // //         println!("{}",arg); // bug in clap, panics
    // // }
    // for arg in cmd.get_arguments() {
    //     let s = arg.get_help().unwrap().to_string();
    //     let v: Vec<&str> = s.split("Details::").collect();
    //     let val_names = arg.get_value_names().unwrap_or(&[]);
    //     let mut pvalnames = false;
    //     match arg.get_num_args() {
    //         None => {}
    //         Some(range) => {
    //             println!("range {:?}", range);
    //             if range != clap::builder::ValueRange::EMPTY {
    //                 pvalnames = true;
    //             }
    //         }
    //     }
    //     if pvalnames {
    //         println!(
    //             "--{} [<{}>]:  {}",
    //             arg.get_long().unwrap(),
    //             val_names[0],
    //             v[0]
    //         );
    //     } else {
    //         println!("--{}: {}", arg.get_long().unwrap(), v[0]);
    //     }
    // }
    let help_str = Args::command().render_help().to_string();
    let v: Vec<&str> = help_str.split('\n').collect();
    for l in v {
        if l.starts_with("  -") || l.starts_with("      --") {
            println!("{}", &l);
        }
    }
}

/// Prints the short help
pub fn help() {
    let help_str = Args::command().render_help().to_string();
    // println!("{}", &help_str);
    // regex to remove shortest pieces "Details:: ... \n  -"
    // regex to remove shortest pieces "Details:: ... \n      --"
    // regex to remove shortest pieces "Details:: ... \nPS:"
    // 2 regex groups: delete and keep.
    // [\S\s]*? ... match anything in a non-greedy fashion
    // stop when either "PS:", "  -" or "      --" is reached
    let re = Regex::new(r"(?P<del>[ ]+Details::[\S\s]*?)(?P<keep>\nPS:|\n  -|\n      --)").unwrap();
    let after = re.replace_all(&help_str, "$keep");
    print!("{}", &after.replace("\n\n", "\n")); // remove empty lines
    println!("Use --manual to get more detailed help information.");
}

/// Prints the long help
pub fn manual() {
    let help_str = Args::command().render_long_help().to_string();
    println!("{}", &help_str);
}

/// Prints the README.md file
pub async fn readme() {
    match reqwest::get(URL_README).await {
        Ok(resp) => {
            debug!("Got README.md file from URL {:?}.", URL_README);
            println!("{}", resp.text().await.unwrap())
        }
        Err(ref e) => {
            println!(
                "Error getting README.md from {:#?}. Reported error {:?}.",
                URL_README, e
            );
        }
    };
}

/// Prints the version information
pub fn version(output: Output) {
    let version = if stdout().is_terminal() {
        get_version().green()
    } else {
        get_version().normal()
    };
    match output {
        Output::Text => {
            println!();
            println!(
                "  _|      _|      _|_|_|                     {}",
                get_prog_without_ext()
            );
            print!("  _|_|  _|_|    _|             _~^~^~_       ");
            println!("a rusty vision of a Matrix CLI client");
            println!(
                "  _|  _|  _|    _|         \\) /  o o  \\ (/   version {}",
                version
            );
            println!(
                "  _|      _|    _|           '_   -   _'     repo {}",
                get_pkg_repository()
            );
            print!("  _|      _|      _|_|_|     / '-----' \\     ");
            println!("please submit PRs to make the vision a reality");
            println!();
        }
        Output::JsonSpec => (),
        _ => println!(
            "{{\"program\": {:?}, \"version\": {:?}, \"repo\": {:?}}}",
            get_prog_without_ext(),
            get_version(),
            get_pkg_repository()
        ),
    }
}

/// Prints the installed version and the latest crates.io-available version
pub fn version_check() {
    println!("Installed version: v{}", get_version());
    let name = env!("CARGO_PKG_NAME");
    let version = env!("CARGO_PKG_VERSION");
    let informer = update_informer::new(registry::Crates, name, version).check_version();
    let avail = "New version is available";
    let uptod = "You are up-to-date.";
    let couldnot = "Could not get latest version.";
    let available;
    let uptodate;
    let couldnotget;
    if stdout().is_terminal() {
        // debug!("stdout is a terminal so we can use color codes")
        available = avail.yellow();
        uptodate = uptod.green();
        couldnotget = couldnot.red();
    } else {
        available = avail.normal();
        uptodate = uptod.normal();
        couldnotget = couldnot.normal();
    }
    match informer {
        Ok(Some(version)) => println!(
            "{} on https://crates.io/crates/{}: {}",
            available, name, version
        ),
        Ok(None) => {
            println!("{uptodate} You already have the latest version.")
        }
        Err(ref e) => println!("{couldnotget} Error reported: {e}."),
    };
}

/// Asks the public for help
pub fn contribute() {
    println!();
    println!(
        "This project is currently only a vision. The Python package {} exists. ",
        get_prog_without_ext()
    );
    println!("The vision is to have a compatible program in Rust. I cannot do it myself, ");
    println!("but I can coordinate and merge your pull requests. Have a look at the repo ");
    println!("{}. Please help! Please contribute ", get_pkg_repository());
    println!("code to make this vision a reality, and to one day have a functional ");
    println!("{} crate. Safe!", get_prog_without_ext());
}

/// If necessary reads homeserver name for login and puts it into the Args.
/// If already set via --homeserver option, then it does nothing.
fn get_homeserver(ap: &mut Args) {
    while ap.homeserver.is_none() {
        print!("Enter your Matrix homeserver (e.g. https://some.homeserver.org): ");
        if let Err(e) = io::stdout().flush() {
            warn!("Warning: Failed to flush stdout: {e}");
        }
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            error!("Error: Unable to read user input");
            continue; // Skip to the next iteration if reading input fails
        }
        let trimmed_input = input.trim();
        if trimmed_input.is_empty() {
            error!("Error: Empty homeserver name is not allowed!");
        } else if let Err(e) = Url::parse(trimmed_input) {
            error!(
                "Error: The syntax is incorrect. Homeserver must be a valid URL! \
                Start with 'http://' or 'https://'. Details: {e}"
            );
        } else {
            ap.homeserver = Some(Url::parse(trimmed_input).unwrap()); // Safe to unwrap since we validated it
            debug!("homeserver is {}", ap.homeserver.as_ref().unwrap());
        }
    }
}

/// If necessary reads user name for login and puts it into the Args.
/// If already set via --user-login option, then it does nothing.
fn get_user_login(ap: &mut Args) {
    while ap.user_login.is_none() {
        print!("Enter your full Matrix username (e.g. @john:some.homeserver.org): ");
        if let Err(e) = io::stdout().flush() {
            warn!("Warning: Failed to flush stdout: {e}");
        }
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            error!("Error: Unable to read user input");
            continue; // Skip to the next iteration if reading input fails
        }
        let trimmed_input = input.trim();
        if trimmed_input.is_empty() {
            error!("Error: Empty username is not allowed!");
        } else if !is_valid_username(trimmed_input) {
            error!("Error: Invalid username format!");
        } else {
            ap.user_login = Some(trimmed_input.to_string());
            debug!("user_login is {trimmed_input}");
        }
    }
}

// validation function for username format
fn is_valid_username(username: &str) -> bool {
    // Check if it starts with '@', contains ':', etc.
    username.starts_with('@') && username.contains(':')
}

/// If necessary reads password for login and puts it into the Args.
/// If already set via --password option, then it does nothing.
fn get_password(ap: &mut Args) {
    while ap.password.is_none() {
        print!("Enter Matrix password for this user: ");
        // Flush stdout to ensure the prompt is displayed
        if let Err(e) = io::stdout().flush() {
            warn!("Warning: Failed to flush stdout: {e}");
        }
        // Handle potential errors from read_password
        match read_password() {
            Ok(password) => {
                let trimmed_password = password.trim();
                if trimmed_password.is_empty() {
                    error!("Error: Empty password is not allowed!");
                } else {
                    ap.password = Some(password);
                    // Hide password from debug log files
                    debug!("password is {}", "******");
                }
            }
            Err(e) => {
                error!("Error reading password: {e}");
            }
        }
    }
}

/// If necessary reads device for login and puts it into the Args.
/// If already set via --device option, then it does nothing.
fn get_device(ap: &mut Args) {
    while ap.device.is_none() {
        print!(
            "Enter your desired name for the Matrix device that \
            is going to be created for you (e.g. {}): ",
            get_prog_without_ext()
        );
        if let Err(e) = io::stdout().flush() {
            warn!("Warning: Failed to flush stdout: {e}");
        }
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            error!("Error: Unable to read user input");
            continue; // Skip to the next iteration if reading input fails
        }
        let trimmed_input = input.trim();
        if trimmed_input.is_empty() {
            error!("Error: Empty device name is not allowed!");
        } else {
            ap.device = Some(trimmed_input.to_string());
            debug!("device is {trimmed_input}");
        }
    }
}

/// If necessary reads room_default for login and puts it into the Args.
/// If already set via --room_default option, then it does nothing.
fn get_room_default(ap: &mut Args) {
    while ap.room_default.is_none() {
        print!(
            "Enter name of one of your Matrix rooms that you want to use as default room  \
            (e.g. !someRoomId:some.homeserver.org): "
        );
        if let Err(e) = io::stdout().flush() {
            warn!("Warning: Failed to flush stdout: {e}");
        }
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            error!("Error: Unable to read user input");
            continue; // Skip to the next iteration if reading input fails
        }
        let trimmed_input = input.trim();
        if trimmed_input.is_empty() {
            error!("Error: Empty name of default room is not allowed!");
        } else if !is_valid_room_name(trimmed_input) {
            error!("Error: Invalid room name format for '{trimmed_input}'! Room name must start with '!' and contain exactly one ':'.");
        } else {
            ap.room_default = Some(trimmed_input.to_string());
            debug!("room_default is '{trimmed_input}'");
        }
    }
}

// Validation function for room name format
fn is_valid_room_name(name: &str) -> bool {
    name.starts_with('!') && name.matches(':').count() == 1
}

/// A room is either specified with --room or the default from credentials file is used
/// On error return None.
fn set_rooms(ap: &mut Args, default_room: &str) {
    debug!("set_rooms()");
    if ap.room.is_empty() {
        ap.room.push(default_room.to_string()); // since --room is empty, use default room from credentials
    }
}

// /// Before get_rooms() is called the rooms should have been updated with set_rooms() first.
// /// Get the user specified rooms (which might either have been specified with --room or
// /// be the default room from the credentials file).
// /// On error return None.
// fn get_rooms(ap: &Args) -> &Vec<String> {
//     debug!("get_rooms()");
//     &ap.room
// }

/// Get the default room id from the credentials file.
/// On error return None.
async fn get_room_default_from_credentials(client: &Client, credentials: &Credentials) -> String {
    let mut room = credentials.room_id.clone();
    convert_to_full_room_id(
        client,
        &mut room,
        credentials.homeserver.host_str().unwrap(),
    )
    .await;
    room
}

/// A user is either specified with --user or the default from credentials file is used
/// On error return None.
fn set_users(ap: &mut Args) {
    debug!("set_users()");
    if ap.user.is_empty() {
        let duser = get_user_default_from_credentials(ap.creds.as_ref().unwrap());
        ap.user.push(duser.to_string()); // since --user is empty, use default user from credentials
    }
}

/// Before get_users() is called the users should have been updated with set_users() first.
/// Get the user specified users (which might either have been specified with --user or
/// be the default user from the credentials file).
/// On error return None.
#[allow(dead_code)]
fn get_users(ap: &Args) -> &Vec<String> {
    debug!("get_users()");
    &ap.user
}

/// Get the default user id from the credentials file.
/// On error return None.
fn get_user_default_from_credentials(credentials: &Credentials) -> OwnedUserId {
    credentials.user_id.clone()
}

/// Convert a vector of aliases that can contain short alias forms into
/// a vector of fully canonical aliases.
/// john and #john will be converted to #john:matrix.server.org.
/// vecstr: the vector of aliases
/// default_host: the default hostname like "matrix.server.org"
fn convert_to_full_room_aliases(vecstr: &mut Vec<String>, default_host: &str) {
    vecstr.retain(|x| !x.trim().is_empty());
    for el in vecstr {
        el.retain(|c| !c.is_whitespace());
        if el.starts_with('!') {
            warn!("A room id was given as alias. {:?}", el);
            continue;
        }
        if !el.starts_with('#') {
            el.insert(0, '#');
        }
        if !el.contains(':') {
            el.push(':');
            el.push_str(default_host);
        }
    }
}

// Replace shortcut "-" with room id of default room
fn replace_minus_with_default_room(vecstr: &mut Vec<String>, default_room: &str) {
    // There is no way to distringuish --get-room-info not being in CLI
    // and --get-room-info being in API without a room.
    // Hence it is not possible to say "if vector is empty let's use the default room".
    // The user has to specify something, we used "-".
    if vecstr.iter().any(|x| x.trim() == "-") {
        vecstr.push(default_room.to_string());
    }
    vecstr.retain(|x| x.trim() != "-");
}

/// Handle the --login CLI argument
pub(crate) async fn cli_login(ap: &mut Args) -> Result<(Client, Credentials), Error> {
    if ap.login.is_none() {
        return Err(Error::UnsupportedCliParameter("--login cannot be empty"));
    }
    if credentials_exist(ap) {
        error!(concat!(
            "Credentials file already exists. You have already logged in in ",
            "the past. No login needed. Skipping login. If you really want to log in ",
            "(i.e. create a new device), then logout first, or move credentials file manually. ",
            "Or just run your command again but without the '--login' option to log in ",
            "via your existing credentials and access token. ",
        ));
        return Err(Error::LoginUnnecessary);
    }
    if !ap.login.is_password() {
        error!(
            "Login option '{:?}' currently not supported. Use '{:?}' for the time being.",
            ap.login,
            Login::Password
        );
        return Err(Error::UnsupportedCliParameter(
            "Used login option currently not supported. Use 'password' for the time being.",
        ));
    }
    // login is Login::Password
    get_homeserver(ap);
    get_user_login(ap);
    get_password(ap);
    get_device(ap); // human-readable device name
    get_room_default(ap);
    // hide password from debug log file // ap.password
    info!(
        "Parameters for login are: {:?} {:?} {:?} {:?} {:?}",
        ap.homeserver, ap.user_login, "******", ap.device, ap.room_default
    );
    let (client, credentials) = crate::login(
        ap,
        &ap.homeserver.clone().ok_or(Error::MissingCliParameter)?,
        &ap.user_login.clone().ok_or(Error::MissingCliParameter)?,
        &ap.password.clone().ok_or(Error::MissingCliParameter)?,
        &ap.device.clone().ok_or(Error::MissingCliParameter)?,
        &ap.room_default.clone().ok_or(Error::MissingCliParameter)?,
    )
    .await?;
    Ok((client, credentials))
}

/// Attempt a restore-login iff the --login CLI argument is missing.
/// In other words try a re-login using the access token from the credentials file.
pub(crate) async fn cli_restore_login(
    credentials: &Credentials,
    ap: &Args,
) -> Result<Client, Error> {
    info!("restore_login implicitly chosen.");
    crate::restore_login(credentials, ap).await
}

/// Handle the --bootstrap CLI argument
pub(crate) async fn cli_bootstrap(client: &Client, ap: &mut Args) -> Result<(), Error> {
    info!("Bootstrap chosen.");
    crate::bootstrap(client, ap).await
}

/// Handle the --verify CLI argument
pub(crate) async fn cli_verify(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Verify chosen.");
    if ap.verify.is_none() {
        return Err(Error::UnsupportedCliParameter(
            "Argument --verify cannot be empty",
        ));
    }
    if !ap.verify.is_manual_device()
        && !ap.verify.is_manual_user()
        && !ap.verify.is_emoji()
        && !ap.verify.is_emoji_req()
    {
        error!(
            "Verify option '{:?}' currently not supported. \
            Use '{:?}', '{:?}', '{:?}' or {:?}' for the time being.",
            ap.verify,
            Verify::ManualDevice,
            Verify::ManualUser,
            Verify::Emoji,
            Verify::EmojiReq
        );
        return Err(Error::UnsupportedCliParameter(
            "Used --verify option is currently not supported",
        ));
    }
    crate::verify(client, ap).await
}

fn trim_newline(s: &mut String) -> &mut String {
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
    s
}

/// Handle the --message CLI argument
pub(crate) async fn cli_message(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Message chosen.");
    if ap.message.is_empty() {
        return Ok(()); // nothing to do
    }
    let mut fmsgs: Vec<String> = Vec::new(); // formatted msgs
    for msg in ap.message.iter() {
        if msg.is_empty() {
            info!("Skipping empty text message.");
            continue;
        };
        if msg == "--" {
            info!("Skipping '--' text message as these are used to separate arguments.");
            continue;
        };
        // - map to - (stdin pipe)
        // \- maps to text r'-', a 1-letter message
        let fmsg = if msg == r"-" {
            let mut line = String::new();
            if stdin().is_terminal() {
                print!("Message: ");
                io::stdout().flush()?;
                io::stdin().read_line(&mut line)?;
            } else {
                io::stdin().read_to_string(&mut line)?;
            }
            // line.trim_end().to_string() // remove /n at end of string
            line.strip_suffix("\r\n")
                .or(line.strip_suffix("\n"))
                .unwrap_or(&line)
                .to_string() // remove /n at end of string
        } else if msg == r"_" {
            let mut eof = false;
            while !eof {
                let mut line = String::new();
                match io::stdin().read_line(&mut line) {
                    // If this function returns Ok(0), the stream has reached EOF.
                    Ok(n) => {
                        if n == 0 {
                            eof = true;
                            debug!("Reached EOF of pipe stream.");
                        } else {
                            debug!(
                                "Read {n} bytes containing \"{}\\n\" from pipe stream.",
                                trim_newline(&mut line.clone())
                            );
                            match message(
                                client,
                                &[line],
                                &ap.room,
                                ap.code,
                                ap.markdown,
                                ap.notice,
                                ap.emote,
                                ap.html,
                            )
                            .await
                            {
                                Ok(()) => {
                                    debug!("message from pipe stream sent successfully");
                                }
                                Err(ref e) => {
                                    error!(
                                        "Error: sending message from pipe stream reported {}",
                                        e
                                    );
                                }
                            }
                        }
                    }
                    Err(ref e) => {
                        error!("Error: reading from pipe stream reported {}", e);
                    }
                }
            }
            "".to_owned()
        } else if msg == r"\-" {
            "-".to_string()
        } else if msg == r"\_" {
            "_".to_string()
        } else if msg == r"\-\-" {
            "--".to_string()
        } else if msg == r"\-\-\-" {
            "---".to_string()
        } else {
            msg.to_string()
        };
        if !fmsg.is_empty() {
            fmsgs.push(fmsg);
        }
    }
    if fmsgs.is_empty() {
        return Ok(()); // nothing to do
    }
    message(
        client,
        &fmsgs,
        &ap.room,
        ap.code,
        ap.markdown,
        ap.notice,
        ap.emote,
        ap.html,
    )
    .await // returning
}

/// Handle the --file CLI argument
pub(crate) async fn cli_file(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("File chosen.");
    if ap.file.is_empty() {
        return Ok(()); // nothing to do
    }
    let mut files: Vec<PathBuf> = Vec::new();
    for filename in &ap.file {
        match filename.as_str() {
            "" => info!("Skipping empty file name."),
            r"-" => files.push(PathBuf::from("-".to_string())),
            r"\-" => files.push(PathBuf::from(r"\-".to_string())),
            _ => files.push(PathBuf::from(filename)),
        }
    }
    // pb: label to attach to a stdin pipe data in case there is data piped in from stdin
    let pb: PathBuf = if !ap.file_name.is_empty() {
        ap.file_name[0].clone()
    } else {
        PathBuf::from("file")
    };
    file(
        client, &files, &ap.room, None, // label, use default filename
        None, // mime, guess it
        &pb,  // label for stdin pipe
    )
    .await // returning
}

/// Handle the --media-upload CLI argument
pub(crate) async fn cli_media_upload(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Media upload chosen.");
    media_upload(client, &ap.media_upload, &ap.mime, ap.output).await // returning
}

/// Handle the --media-download once CLI argument
pub(crate) async fn cli_media_download(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Media download chosen.");
    media_download(client, &ap.media_download, &ap.file_name, ap.output).await // returning
}

/// Handle the --media-delete once CLI argument
pub(crate) async fn cli_media_delete(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Media delete chosen.");
    media_delete(client, &ap.media_delete, ap.output).await // returning
}

/// Handle the --media-mxc-to-http once CLI argument
pub(crate) async fn cli_media_mxc_to_http(ap: &Args) -> Result<(), Error> {
    info!("Media mxc_to_http chosen.");
    media_mxc_to_http(
        &ap.media_mxc_to_http,
        &ap.creds.as_ref().unwrap().homeserver,
        ap.output,
    )
    .await // returning
}

/// Handle the --listen once CLI argument
pub(crate) async fn cli_listen_once(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Listen Once chosen.");
    listen_once(client, ap.listen_self, crate::whoami(ap), ap.output).await // returning
}

/// Handle the --listen forever CLI argument
pub(crate) async fn cli_listen_forever(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Listen Forever chosen.");
    listen_forever(client, ap.listen_self, crate::whoami(ap), ap.output).await
    // returning
}

/// Handle the --listen tail CLI argument
pub(crate) async fn cli_listen_tail(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Listen Tail chosen.");
    listen_tail(
        client,
        &ap.room,
        ap.tail,
        ap.listen_self,
        crate::whoami(ap),
        ap.output,
    )
    .await // returning
}

/// Handle the --listen all CLI argument
pub(crate) async fn cli_listen_all(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Listen All chosen.");
    listen_all(
        client,
        &ap.room,
        ap.listen_self,
        crate::whoami(ap),
        ap.output,
    )
    .await // returning
}

/// Handle the --devices CLI argument
pub(crate) async fn cli_devices(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Devices chosen.");
    crate::devices(client, ap.output).await // returning
}

/// Utility function, returns user_id of itself
pub(crate) fn whoami(ap: &Args) -> OwnedUserId {
    ap.creds.as_ref().unwrap().user_id.clone()
}

/// Handle the --whoami CLI argument
pub(crate) fn cli_whoami(ap: &Args) -> Result<(), Error> {
    info!("Whoami chosen.");
    let whoami = crate::whoami(ap);
    match ap.output {
        Output::Text => println!("{}", whoami),
        Output::JsonSpec => (),
        _ => println!("{{\"user_id\": \"{}\"}}", whoami),
    }
    Ok(())
}

/// Handle the --get-room-info CLI argument
pub(crate) async fn cli_get_room_info(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Get-room-info chosen.");
    // note that get_room_info vector is NOT empty.
    // If it were empty this function would not be called.
    crate::get_room_info(client, &ap.get_room_info, ap.output).await
}

/// Handle the --rooms CLI argument
pub(crate) async fn cli_rooms(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Rooms chosen.");
    crate::rooms(client, ap.output).await
}

/// Handle the --invited-rooms CLI argument
pub(crate) async fn cli_invited_rooms(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Invited-rooms chosen.");
    crate::invited_rooms(client, ap.output).await
}

/// Handle the --joined-rooms CLI argument
pub(crate) async fn cli_joined_rooms(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Joined-rooms chosen.");
    crate::joined_rooms(client, ap.output).await
}

/// Handle the --left-rooms CLI argument
pub(crate) async fn cli_left_rooms(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Left-rooms chosen.");
    crate::left_rooms(client, ap.output).await
}

/// Handle the --room-create CLI argument
pub(crate) async fn cli_room_create(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Room-create chosen.");
    crate::room_create(
        client,
        false,
        match &ap.visibility {
            Visibility::Private => !ap.plain.unwrap_or(false), // private rooms are encrypted by default
            Visibility::Public => !ap.plain.unwrap_or(true),   // public rooms are plain by default
            _ => !ap.plain.unwrap_or(false),
        },
        &[],
        &ap.room_create,
        &ap.name,
        &ap.topic,
        ap.output,
        ap.visibility.clone(),
    )
    .await
}

/// Handle the --room-create CLI argument
pub(crate) async fn cli_room_dm_create(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Room-dm-create chosen.");
    crate::room_create(
        client,
        true,
        match &ap.visibility {
            Visibility::Private => !ap.plain.unwrap_or(false), // private rooms are encrypted by default
            Visibility::Public => !ap.plain.unwrap_or(true),   // public rooms are plain by default
            _ => !ap.plain.unwrap_or(false),
        },
        &ap.room_dm_create,
        &ap.alias,
        &ap.name,
        &ap.topic,
        ap.output,
        ap.visibility.clone(),
    )
    .await
}

/// Handle the --room-leave CLI argument
pub(crate) async fn cli_room_leave(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Room-leave chosen.");
    crate::room_leave(client, &ap.room_leave, ap.output).await
}

/// Handle the --room-forget CLI argument
pub(crate) async fn cli_room_forget(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Room-forget chosen.");
    crate::room_forget(client, &ap.room_forget, ap.output).await
}

/// Handle the --room-invite CLI argument
pub(crate) async fn cli_room_invite(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Room-invite chosen.");
    crate::room_invite(client, &ap.room_invite, &ap.user, ap.output).await
}

/// Handle the --room-join CLI argument
pub(crate) async fn cli_room_join(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Room-join chosen.");
    crate::room_join(client, &ap.room_join, ap.output).await
}

/// Handle the --room-ban CLI argument
pub(crate) async fn cli_room_ban(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Room-ban chosen.");
    crate::room_ban(client, &ap.room_ban, &ap.user, ap.output).await
}

/// Handle the --room-unban CLI argument
pub(crate) async fn cli_room_unban(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Room-unban chosen.");
    crate::room_unban(client, &ap.room_unban, &ap.user, ap.output).await
}

/// Handle the --room-kick CLI argument
pub(crate) async fn cli_room_kick(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Room-kick chosen.");
    crate::room_kick(client, &ap.room_kick, &ap.user, ap.output).await
}

/// Handle the --room-resolve_alias CLI argument
pub(crate) async fn cli_room_resolve_alias(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Room-resolve-alias chosen.");
    crate::room_resolve_alias(client, &ap.room_resolve_alias, ap.output).await
}

/// Handle the --room-enable-encryption CLI argument
pub(crate) async fn cli_room_enable_encryption(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Room-enable-encryption chosen.");
    crate::room_enable_encryption(client, &ap.room_enable_encryption, ap.output).await
}

/// Handle the --get-avatar CLI argument
pub(crate) async fn cli_get_avatar(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Get-avatar chosen.");
    if let Some(path) = ap.get_avatar.as_ref() {
        crate::get_avatar(client, path, ap.output).await
    } else {
        Err(Error::MissingCliParameter)
    }
}

/// Handle the --set-avatar CLI argument
pub(crate) async fn cli_set_avatar(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Set-avatar chosen.");
    if let Some(path) = ap.set_avatar.as_ref() {
        crate::set_avatar(client, path, ap.output).await
    } else {
        Err(Error::MissingCliParameter)
    }
}

/// Handle the --get-avatar-url CLI argument
pub(crate) async fn cli_get_avatar_url(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Get-avatar-url chosen.");
    crate::get_avatar_url(client, ap.output).await
}

/// Handle the --set-avatar_url CLI argument
pub(crate) async fn cli_set_avatar_url(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Set-avatar-url chosen.");
    if let Some(mxc_uri) = ap.set_avatar_url.as_ref() {
        crate::set_avatar_url(client, mxc_uri, ap.output).await
    } else {
        Err(Error::MissingCliParameter)
    }
}

/// Handle the --unset-avatar_url CLI argument
pub(crate) async fn cli_unset_avatar_url(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Unset-avatar-url chosen.");
    crate::unset_avatar_url(client, ap.output).await
}

/// Handle the --get-display-name CLI argument
pub(crate) async fn cli_get_display_name(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Get-display-name chosen.");
    crate::get_display_name(client, ap.output).await
}

/// Handle the --set-display-name CLI argument
pub(crate) async fn cli_set_display_name(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Set-display-name chosen.");
    if let Some(name) = ap.set_display_name.as_ref() {
        crate::set_display_name(client, name, ap.output).await
    } else {
        Err(Error::MissingCliParameter)
    }
}

/// Handle the --get-profile CLI argument
pub(crate) async fn cli_get_profile(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Get-profile chosen.");
    crate::get_profile(client, ap.output).await
}

/// Handle the --get-masterkey CLI argument
pub(crate) async fn cli_get_masterkey(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Get-masterkey chosen.");
    crate::get_masterkey(
        client,
        ap.creds.as_ref().unwrap().user_id.clone(),
        ap.output,
    )
    .await
}

/// Handle the --room-get-visibility CLI argument
pub(crate) async fn cli_room_get_visibility(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Room-get-visibility chosen.");
    crate::room_get_visibility(client, &ap.room_get_visibility, ap.output).await
}

/// Handle the --room-get-state CLI argument
pub(crate) async fn cli_room_get_state(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Room-get-state chosen.");
    crate::room_get_state(client, &ap.room_get_state, ap.output).await
}

/// Handle the --joined-members CLI argument
pub(crate) async fn cli_joined_members(client: &Client, ap: &Args) -> Result<(), Error> {
    info!("Joined-members chosen.");
    crate::joined_members(client, &ap.joined_members, ap.output).await
}

/// Handle the --delete-device CLI argument
pub(crate) async fn cli_delete_device(client: &Client, ap: &mut Args) -> Result<(), Error> {
    info!("Delete-device chosen.");
    crate::delete_devices_pre(client, ap).await
}

/// Handle the --logout CLI argument
pub(crate) async fn cli_logout(client: &Client, ap: &mut Args) -> Result<(), Error> {
    info!("Logout chosen.");
    if ap.logout.is_none() {
        return Ok(());
    }
    if ap.logout.is_all() {
        // delete_device list will be overwritten, but that is okay because
        // logout is the last function in main.
        ap.delete_device = vec!["*".to_owned()];
        match cli_delete_device(client, ap).await {
            Ok(_) => info!("Logout caused all devices to be deleted."),
            Err(e) => error!(
                "Error: Failed to delete all devices, but we remove local device id anyway. {:?}",
                e
            ),
        }
    }
    crate::logout(client, ap).await
}

/// We need your code contributions! Please add features and make PRs! :pray: :clap:
#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut ap = Args::parse();
    let mut errcount = 0;
    let mut result: Result<(), Error> = Ok(());

    // handle log level and debug options
    let env_org_rust_log = env::var("RUST_LOG").unwrap_or_default().to_uppercase();
    // println!("Original log_level option is {:?}", ap.log_level);
    // println!("Original RUST_LOG is {:?}", &env_org_rust_log);
    match ap.debug.cmp(&1) {
        Ordering::Equal => {
            // -d overwrites --log-level
            let llvec = vec![LogLevel::Debug];
            ap.log_level = Some(llvec);
        }
        Ordering::Greater => {
            // -d overwrites --log-level
            let mut llvec = vec![LogLevel::Debug];
            llvec.push(LogLevel::Debug);
            ap.log_level = Some(llvec);
        }
        Ordering::Less => (),
    }
    match ap.log_level.clone() {
        None => {
            tracing_subscriber::fmt()
                .with_writer(io::stderr)
                .with_env_filter(EnvFilter::from_default_env()) // support the standard RUST_LOG env variable
                .init();
            debug!("Neither --debug nor --log-level was used. Using environment variable RUST_LOG.");
        }
        Some(llvec) => {
            if llvec.len() == 1 {
                if llvec[0].is_none() {
                    return Err(Error::UnsupportedCliParameter(
                        "Value 'none' not allowed for --log-level argument",
                    ));
                }
                // .with_env_filter("matrix_commander_rs=debug") // only set matrix_commander_rs
                let mut rlogstr: String = BIN_NAME_UNDERSCORE.to_owned();
                rlogstr.push('='); // add char
                rlogstr.push_str(&llvec[0].to_string());
                tracing_subscriber::fmt()
                    .with_writer(io::stderr)
                    .with_env_filter(rlogstr.clone()) // support the standard RUST_LOG env variable for default value
                    .init();
                debug!(
                    "The --debug or --log-level was used once or with one value. \
                    Specifying logging equivalent to RUST_LOG setting of '{}'.",
                    rlogstr
                );
            } else {
                if llvec[0].is_none() || llvec[1].is_none() {
                    return Err(Error::UnsupportedCliParameter(
                        "Value 'none' not allowed for --log-level argument",
                    ));
                }
                // RUST_LOG="error,matrix_commander_rs=debug"  .. This will only show matrix-comander-rs
                // debug info, and erors for all other modules
                let mut rlogstr: String = llvec[1].to_string().to_owned();
                rlogstr.push(','); // add char
                rlogstr.push_str(BIN_NAME_UNDERSCORE);
                rlogstr.push('=');
                rlogstr.push_str(&llvec[0].to_string());
                tracing_subscriber::fmt()
                    .with_writer(io::stderr)
                    .with_env_filter(rlogstr.clone())
                    .init();
                debug!(
                    "The --debug or --log-level was used twice or with two values. \
                    Specifying logging equivalent to RUST_LOG setting of '{}'.",
                    rlogstr
                );
            }
            if llvec.len() > 2 {
                debug!("The --log-level option was incorrectly used more than twice. Ignoring third and further use.")
            }
        }
    }
    if ap.debug > 0 {
        info!("The --debug option overwrote the --log-level option.")
    }
    if ap.debug > 2 {
        debug!("The --debug option was incorrectly used more than twice. Ignoring third and further use.")
    }
    debug!("Original RUST_LOG env var is '{}'", env_org_rust_log);
    debug!(
        "Final RUST_LOG env var is '{}'",
        env::var("RUST_LOG").unwrap_or_default().to_uppercase()
    );
    debug!("Final log-level option is {:?}", ap.log_level);
    if enabled!(Level::TRACE) {
        debug!(
            "Log level of module {} is set to TRACE.",
            get_prog_without_ext()
        );
    } else if enabled!(Level::DEBUG) {
        debug!(
            "Log level of module {} is set to DEBUG.",
            get_prog_without_ext()
        );
    }
    debug!("Version is {}", get_version());
    debug!("Package name is {}", get_pkg_name());
    debug!("Repo is {}", get_pkg_repository());
    debug!("contribute flag is {}", ap.contribute);
    debug!("version option is set to {:?}", ap.version);
    debug!("debug flag is {}", ap.debug);
    debug!("log-level option is {:?}", ap.log_level);
    debug!("verbose option is {}", ap.verbose);
    debug!("plain flag is {:?}", ap.plain);
    debug!("credentials option is {:?}", ap.credentials);
    debug!("store option is {:?}", ap.store);
    debug!("login option is {:?}", ap.login);
    debug!("bootstrap flag is {:?}", ap.bootstrap);
    debug!("verify flag is {:?}", ap.verify);
    debug!("message option is {:?}", ap.message);
    debug!("logout option is {:?}", ap.logout);
    debug!("homeserver option is {:?}", ap.homeserver);
    debug!("user-login option is {:?}", ap.user_login);
    debug!("password option is {:?}", ap.password);
    debug!("device option is {:?}", ap.device);
    debug!("room-default option is {:?}", ap.room_default);
    debug!("devices flag is {:?}", ap.devices);
    debug!("timeout option is {:?}", ap.timeout);
    debug!("markdown flag is {:?}", ap.markdown);
    debug!("code flag is {:?}", ap.code);
    debug!("room option is {:?}", ap.room);
    debug!("file option is {:?}", ap.file);
    debug!("notice flag is {:?}", ap.notice);
    debug!("emote flag is {:?}", ap.emote);
    debug!("sync option is {:?}", ap.sync);
    debug!("listen option is {:?}", ap.listen);
    debug!("tail option is {:?}", ap.tail);
    debug!("listen-self flag is {:?}", ap.listen_self);
    debug!("whoami flag is {:?}", ap.whoami);
    debug!("output option is {:?}", ap.output);
    debug!("get-room-info option is {:?}", ap.get_room_info);
    debug!("file-name option is {:?}", ap.file_name);
    debug!("room-create option is {:?}", ap.room_create);
    debug!("room-dm-create option is {:?}", ap.room_dm_create);
    debug!("room-leave option is {:?}", ap.room_leave);
    debug!("room-forget option is {:?}", ap.room_forget);
    debug!("room-invite option is {:?}", ap.room_invite);
    debug!("room-join option is {:?}", ap.room_join);
    debug!("room-ban option is {:?}", ap.room_ban);
    debug!("room-unban option is {:?}", ap.room_unban);
    debug!("room-kick option is {:?}", ap.room_kick);
    debug!("room-resolve-alias option is {:?}", ap.room_resolve_alias);
    debug!(
        "room-enable-encryption option is {:?}",
        ap.room_enable_encryption
    );
    debug!("alias option is {:?}", ap.alias);
    debug!("name option is {:?}", ap.name);
    debug!("topic-create option is {:?}", ap.topic);
    debug!("rooms option is {:?}", ap.rooms);
    debug!("invited-rooms option is {:?}", ap.invited_rooms);
    debug!("joined-rooms option is {:?}", ap.joined_rooms);
    debug!("left-rooms option is {:?}", ap.left_rooms);
    debug!("room-get-visibility option is {:?}", ap.room_get_visibility);
    debug!("room-get-state option is {:?}", ap.room_get_state);
    debug!("joined-members option is {:?}", ap.joined_members);
    debug!("delete-device option is {:?}", ap.delete_device);
    debug!("user option is {:?}", ap.user);
    debug!("get-avatar option is {:?}", ap.get_avatar);
    debug!("set-avatar option is {:?}", ap.set_avatar);
    debug!("get-avatar_url flag is {:?}", ap.get_avatar_url);
    debug!("set-avatar_url option is {:?}", ap.set_avatar_url);
    debug!("unset-avatar_url flag is {:?}", ap.unset_avatar_url);
    debug!("get-display-name option is {:?}", ap.get_display_name);
    debug!("set-display-name option is {:?}", ap.set_display_name);
    debug!("get-profile option is {:?}", ap.get_profile);
    debug!("media-upload option is {:?}", ap.media_upload);
    debug!("media-download option is {:?}", ap.media_download);
    debug!("media-delete option is {:?}", ap.media_delete);
    debug!("media-mxc-to-http option is {:?}", ap.media_mxc_to_http);
    debug!("mime option is {:?}", ap.mime);
    debug!("get-masterkey option is {:?}", ap.get_masterkey);

    match ap.version {
        None => (),                              // do nothing
        Some(None) => crate::version(ap.output), // print version
        Some(Some(Version::Check)) => crate::version_check(),
    }
    if ap.contribute {
        crate::contribute();
    };
    if ap.usage {
        crate::usage();
        return Ok(());
    };
    if ap.help {
        crate::help();
        return Ok(());
    };
    if ap.manual {
        crate::manual();
        return Ok(());
    };
    if ap.readme {
        crate::readme().await;
        return Ok(());
    };

    // -m not used but data being piped into stdin?
    if ap.message.is_empty() && !stdin().is_terminal() {
        // make it more compatible with the Python version of this tool
        debug!(
            "-m is empty, but there is something piped into stdin. Let's assume '-m -' \
            and read and send the information piped in on stdin."
        );
        ap.message.push("-".to_string());
    };
    debug!(
        "message {:?}, is_terminal() = {:?} (if it not the terminal than it is a pipe on stdin)",
        ap.message,
        stdin().is_terminal()
    );

    if !(!ap.login.is_none()
        // get actions
        || ap.whoami
        || ap.bootstrap
        || !ap.verify.is_none()
        || ap.devices
        || !ap.get_room_info.is_empty()
        || ap.rooms
        || ap.invited_rooms
        || ap.joined_rooms
        || ap.left_rooms
        || !ap.room_get_visibility.is_empty()
        || !ap.room_get_state.is_empty()
        || !ap.joined_members.is_empty()
        || !ap.room_resolve_alias.is_empty()
        || ap.get_avatar.is_some()
        || ap.get_avatar_url
        || ap.get_display_name
        || ap.get_profile
        || !ap.media_download.is_empty()
        || !ap.media_mxc_to_http.is_empty()
        || ap.get_masterkey
        // set actions
        || !ap.room_create.is_empty()
        || !ap.room_dm_create.is_empty()
        || !ap.room_leave.is_empty()
        || !ap.room_forget.is_empty()
        || !ap.room_invite.is_empty()
        || !ap.room_join.is_empty()
        || !ap.room_ban.is_empty()
        || !ap.room_unban.is_empty()
        || !ap.room_kick.is_empty()
        || !ap.delete_device.is_empty()
        || ap.set_avatar.is_some()
        || ap.set_avatar_url.is_some()
        || ap.unset_avatar_url
        || ap.set_display_name.is_some()
        || !ap.room_enable_encryption.is_empty()
        || !ap.media_upload.is_empty()
        || !ap.media_delete.is_empty()
        // send and listen actions
        || !ap.message.is_empty()
        || !ap.file.is_empty()
        || ap.listen.is_once()
        || ap.listen.is_forever()
        || ap.listen.is_tail()
        || ap.tail > 0
        || ap.listen.is_all()
        || !ap.logout.is_none())
    {
        debug!("There are no more actions to take. No need to connect to server. Quitting.");
        debug!("Good bye");
        return Ok(());
    }
    let (clientres, credentials) = if !ap.login.is_none() {
        match crate::cli_login(&mut ap).await {
            Ok((client, credentials)) => (Ok(client), credentials),
            Err(ref e) => {
                error!(
                    "Login to server failed or credentials information could not be \
                    written to disk. Check your arguments and try --login again. \
                    Reported error is: {:?}",
                    e
                );
                return Err(Error::LoginFailed);
            }
        }
    } else if let Ok(credentials) = restore_credentials(&ap) {
        (
            crate::cli_restore_login(&credentials, &ap).await,
            credentials,
        )
    } else {
        error!(
            "Credentials file does not exists or cannot be read. \
            Consider doing a '--logout' to clean up, then perform a '--login'."
        );
        return Err(Error::LoginFailed);
    };
    ap.creds = Some(credentials);

    // Place all the calls here that work without a server connection
    // whoami: works even without client (server connection)
    if ap.whoami {
        match crate::cli_whoami(&ap) {
            Ok(ref _n) => debug!("crate::whoami successful"),
            Err(e) => {
                error!("Error: crate::whoami reported {}", e);
                errcount += 1;
                result = Err(e);
            }
        };
    };

    convert_to_full_mxc_uris(
        &mut ap.media_mxc_to_http,
        ap.creds.as_ref().unwrap().homeserver.host_str().unwrap(),
    )
    .await; // convert short mxcs to full mxc uris

    // media_mxc_to_http works without client (server connection)
    if !ap.media_mxc_to_http.is_empty() {
        match crate::cli_media_mxc_to_http(&ap).await {
            Ok(ref _n) => debug!("crate::media_mxc_to_http successful"),
            Err(e) => {
                error!("Error: crate::media_mxc_to_http reported {}", e);
                errcount += 1;
                result = Err(e);
            }
        };
    };

    // match clientres() {
    //     Ok(ref _n) => {
    //     }
    //     Err(ref e) => {
    //     }
    // };

    match clientres {
        Ok(client) => {
            debug!("A valid client connection has been established with server.");
            // pre-processing of CLI arguments, filtering, replacing shortcuts, etc.
            let default_room =
                get_room_default_from_credentials(&client, ap.creds.as_ref().unwrap()).await;
            // Todo: port number is not handled in hostname, could be matrix.server.org:90
            let creds = ap.creds.clone().unwrap();
            let hostname = creds.homeserver.host_str().unwrap(); // matrix.server.org
            set_rooms(&mut ap, &default_room); // if no rooms in --room, set rooms to default room from credentials file
            set_users(&mut ap); // if no users in --user, set users to default user from credentials file

            replace_minus_with_default_room(&mut ap.room_leave, &default_room); // convert '-' to default room
            convert_to_full_room_ids(&client, &mut ap.room_leave, hostname).await; // convert short ids, short aliases and aliases to full room ids

            replace_minus_with_default_room(&mut ap.room_forget, &default_room); // convert '-' to default room
            convert_to_full_room_ids(&client, &mut ap.room_forget, hostname).await; // convert short ids, short aliases and aliases to full room ids

            convert_to_full_room_aliases(&mut ap.room_resolve_alias, hostname); // convert short aliases to full aliases

            replace_minus_with_default_room(&mut ap.room_enable_encryption, &default_room); // convert '-' to default room
            convert_to_full_room_ids(&client, &mut ap.room_enable_encryption, hostname).await; // convert short ids, short aliases and aliases to full room ids

            replace_minus_with_default_room(&mut ap.get_room_info, &default_room); // convert '-' to default room
            convert_to_full_room_ids(&client, &mut ap.get_room_info, hostname).await; // convert short ids, short aliases and aliases to full room ids

            replace_minus_with_default_room(&mut ap.room_invite, &default_room); // convert '-' to default room
            convert_to_full_room_ids(&client, &mut ap.room_invite, hostname).await; // convert short ids, short aliases and aliases to full room ids

            replace_minus_with_default_room(&mut ap.room_join, &default_room); // convert '-' to default room
            convert_to_full_room_ids(&client, &mut ap.room_join, hostname).await; // convert short ids, short aliases and aliases to full room ids

            replace_minus_with_default_room(&mut ap.room_ban, &default_room); // convert '-' to default room
            convert_to_full_room_ids(&client, &mut ap.room_ban, hostname).await; // convert short ids, short aliases and aliases to full room ids

            replace_minus_with_default_room(&mut ap.room_unban, &default_room); // convert '-' to default room
            convert_to_full_room_ids(&client, &mut ap.room_unban, hostname).await; // convert short ids, short aliases and aliases to full room ids

            replace_minus_with_default_room(&mut ap.room_kick, &default_room); // convert '-' to default room
            convert_to_full_room_ids(&client, &mut ap.room_kick, hostname).await; // convert short ids, short aliases and aliases to full room ids

            replace_minus_with_default_room(&mut ap.room_get_visibility, &default_room); // convert '-' to default room
            replace_star_with_rooms(&client, &mut ap.room_get_visibility); // convert '*' to full list of rooms
            convert_to_full_room_ids(&client, &mut ap.room_get_visibility, hostname).await; // convert short ids, short aliases and aliases to full room ids

            replace_minus_with_default_room(&mut ap.room_get_state, &default_room); // convert '-' to default room
            replace_star_with_rooms(&client, &mut ap.room_get_state); // convert '*' to full list of rooms
            convert_to_full_room_ids(&client, &mut ap.room_get_state, hostname).await; // convert short ids, short aliases and aliases to full room ids

            replace_minus_with_default_room(&mut ap.joined_members, &default_room); // convert '-' to default room
            replace_star_with_rooms(&client, &mut ap.joined_members); // convert '*' to full list of rooms
            convert_to_full_room_ids(&client, &mut ap.joined_members, hostname).await; // convert short ids, short aliases and aliases to full room ids

            convert_to_full_user_ids(&mut ap.room_dm_create, hostname);
            ap.room_dm_create.retain(|x| !x.trim().is_empty());

            convert_to_full_alias_ids(&mut ap.alias, hostname);
            ap.alias.retain(|x| !x.trim().is_empty());

            convert_to_full_mxc_uris(&mut ap.media_download, hostname).await; // convert short mxcs to full mxc uris

            convert_to_full_mxc_uris(&mut ap.media_delete, hostname).await; // convert short mxcs to full mxc uris

            if ap.tail > 0 {
                // overwrite --listen if user has chosen both
                if !ap.listen.is_never() && !ap.listen.is_tail() {
                    warn!(
                        "Two contradicting listening methods were specified. \
                    Overwritten with --tail. Will use '--listen tail'. {:?} {}",
                        ap.listen, ap.tail
                    )
                }
                ap.listen = Listen::Tail
            }

            // top-priority actions

            if ap.bootstrap {
                match crate::cli_bootstrap(&client, &mut ap).await {
                    Ok(ref _n) => debug!("crate::bootstrap successful"),
                    Err(e) => {
                        error!("Error: crate::bootstrap reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if !ap.verify.is_none() {
                match crate::cli_verify(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::verify successful"),
                    Err(e) => {
                        error!("Error: crate::verify reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            // get actions

            if ap.devices {
                match crate::cli_devices(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::devices successful"),
                    Err(e) => {
                        error!("Error: crate::devices reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if !ap.get_room_info.is_empty() {
                match crate::cli_get_room_info(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::get_room_info successful"),
                    Err(e) => {
                        error!("Error: crate::get_room_info reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if ap.rooms {
                match crate::cli_rooms(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::rooms successful"),
                    Err(e) => {
                        error!("Error: crate::rooms reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if ap.invited_rooms {
                match crate::cli_invited_rooms(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::invited_rooms successful"),
                    Err(e) => {
                        error!("Error: crate::invited_rooms reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if ap.joined_rooms {
                match crate::cli_joined_rooms(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::joined_rooms successful"),
                    Err(e) => {
                        error!("Error: crate::joined_rooms reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if ap.left_rooms {
                match crate::cli_left_rooms(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::left_rooms successful"),
                    Err(e) => {
                        error!("Error: crate::left_rooms reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if !ap.room_get_visibility.is_empty() {
                match crate::cli_room_get_visibility(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::room_get_visibility successful"),
                    Err(e) => {
                        error!("Error: crate::room_get_visibility reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if !ap.room_get_state.is_empty() {
                match crate::cli_room_get_state(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::room_get_state successful"),
                    Err(e) => {
                        error!("Error: crate::room_get_state reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if !ap.joined_members.is_empty() {
                match crate::cli_joined_members(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::joined_members successful"),
                    Err(e) => {
                        error!("Error: crate::joined_members reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if !ap.room_resolve_alias.is_empty() {
                match crate::cli_room_resolve_alias(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::room_resolve_alias successful"),
                    Err(e) => {
                        error!("Error: crate::room_resolve_alias reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if ap.get_avatar.is_some() {
                match crate::cli_get_avatar(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::get_avatar successful"),
                    Err(e) => {
                        error!("Error: crate::get_avatar reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if ap.get_avatar_url {
                match crate::cli_get_avatar_url(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::get_avatar_url successful"),
                    Err(e) => {
                        error!("Error: crate::get_avatar_url reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if ap.get_display_name {
                match crate::cli_get_display_name(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::get_display_name successful"),
                    Err(e) => {
                        error!("Error: crate::get_display_name reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if ap.get_profile {
                match crate::cli_get_profile(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::get_profile successful"),
                    Err(e) => {
                        error!("Error: crate::get_profile reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if ap.get_masterkey {
                match crate::cli_get_masterkey(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::get_masterkey successful"),
                    Err(e) => {
                        error!("Error: crate::get_masterkey reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if !ap.media_download.is_empty() {
                match crate::cli_media_download(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::media_download successful"),
                    Err(e) => {
                        error!("Error: crate::media_download reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            // set actions

            if !ap.room_create.is_empty() {
                match crate::cli_room_create(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::room_create successful"),
                    Err(e) => {
                        error!("Error: crate::room_create reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if !ap.room_dm_create.is_empty() {
                match crate::cli_room_dm_create(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::room_dm_create successful"),
                    Err(e) => {
                        error!("Error: crate::room_dm_create reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if !ap.room_leave.is_empty() {
                error!(
                    "There is a bug in the matrix-sdk library and hence this is not working \
                properly at the moment. It will start working once matrix-sdk v0.7 is released."
                );
                match crate::cli_room_leave(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::room_leave successful"),
                    Err(e) => {
                        error!("Error: crate::room_leave reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if !ap.room_forget.is_empty() {
                error!(
                    "There is a bug in the matrix-sdk library and hence this is not working \
                properly at the moment. It might start working once matrix-sdk v0.7 is released."
                );
                match crate::cli_room_forget(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::room_forget successful"),
                    Err(e) => {
                        error!("Error: crate::room_forget reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if !ap.room_invite.is_empty() {
                match crate::cli_room_invite(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::room_invite successful"),
                    Err(e) => {
                        error!("Error: crate::room_invite reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if !ap.room_join.is_empty() {
                match crate::cli_room_join(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::room_join successful"),
                    Err(e) => {
                        error!("Error: crate::room_join reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if !ap.room_ban.is_empty() {
                match crate::cli_room_ban(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::room_ban successful"),
                    Err(e) => {
                        error!("Error: crate::room_ban reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if !ap.room_unban.is_empty() {
                match crate::cli_room_unban(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::room_unban successful"),
                    Err(e) => {
                        error!("Error: crate::room_unban reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if !ap.room_kick.is_empty() {
                match crate::cli_room_kick(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::room_kick successful"),
                    Err(e) => {
                        error!("Error: crate::room_kick reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if !ap.delete_device.is_empty() {
                match crate::cli_delete_device(&client, &mut ap).await {
                    Ok(ref _n) => debug!("crate::delete_device successful"),
                    Err(e) => {
                        error!("Error: crate::delete_device reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if ap.set_avatar.is_some() {
                match crate::cli_set_avatar(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::set_avatar successful"),
                    Err(e) => {
                        error!("Error: crate::set_avatar reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if ap.set_avatar_url.is_some() {
                match crate::cli_set_avatar_url(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::set_avatar_url successful"),
                    Err(e) => {
                        error!("Error: crate::set_avatar_url reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if ap.unset_avatar_url {
                match crate::cli_unset_avatar_url(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::set_avatar_url successful"),
                    Err(e) => {
                        error!("Error: crate::set_avatar_url reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if ap.set_display_name.is_some() {
                match crate::cli_set_display_name(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::set_display_name successful"),
                    Err(e) => {
                        error!("Error: crate::set_display_name reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if !ap.room_enable_encryption.is_empty() {
                match crate::cli_room_enable_encryption(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::room_enable_encryption successful"),
                    Err(e) => {
                        error!("Error: crate::room_enable_encryption reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if !ap.media_upload.is_empty() {
                match crate::cli_media_upload(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::media_upload successful"),
                    Err(e) => {
                        error!("Error: crate::media_upload reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if !ap.media_delete.is_empty() {
                match crate::cli_media_delete(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::media_delete successful"),
                    Err(e) => {
                        error!("Error: crate::media_delete reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            // send text message(s)
            if !ap.message.is_empty() {
                match crate::cli_message(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::message successful"),
                    Err(e) => {
                        error!("Error: crate::message reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            // send file(s)
            if !ap.file.is_empty() {
                match crate::cli_file(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::file successful"),
                    Err(e) => {
                        error!("Error: crate::file reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            // listen once
            if ap.listen.is_once() {
                match crate::cli_listen_once(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::listen_once successful"),
                    Err(e) => {
                        error!("Error: crate::listen_once reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            // listen forever
            if ap.listen.is_forever() {
                match crate::cli_listen_forever(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::listen_forever successful"),
                    Err(e) => {
                        error!("Error: crate::listen_forever reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            // listen tail
            if ap.listen.is_tail() {
                match crate::cli_listen_tail(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::listen_tail successful"),
                    Err(e) => {
                        error!("Error: crate::listen_tail reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            // listen all
            if ap.listen.is_all() {
                match crate::cli_listen_all(&client, &ap).await {
                    Ok(ref _n) => debug!("crate::listen_all successful"),
                    Err(e) => {
                        error!("Error: crate::listen_all reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };

            if !ap.logout.is_none() {
                match crate::cli_logout(&client, &mut ap).await {
                    Ok(ref _n) => debug!("crate::logout successful"),
                    Err(e) => {
                        error!("Error: crate::logout reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            }
        } // Ok(client) =>
        Err(e) => {
            info!(
                "Most operations will be skipped because you don't have a valid client connection."
            );
            error!("Error: {}", e);
            errcount += 1;
            result = Err(e);
            // result = Err(Error::InvalidClientConnection);
            // don't quit yet, don't return Err(Error::LoginFailed);
            // whoami still works without server connection
            // whoami already called above
            // logout can partially be done without server connection
            if !ap.logout.is_none() {
                match logout_local(&ap) {
                    Ok(ref _n) => debug!("crate::logout_local successful"),
                    Err(e) => {
                        error!("Error: crate::logout_local reported {}", e);
                        errcount += 1;
                        result = Err(e);
                    }
                };
            };
        } // Err(e) =>
    } // match clientres
    let plural = if errcount == 1 { "" } else { "s" };
    if errcount > 0 {
        error!("Encountered {} error{}.", errcount, plural);
    } else {
        debug!("Encountered {} error{}.", errcount, plural);
    }
    debug!("Good bye");
    result
}

/// Future test cases will be put here
#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    // for testing async functions
    // see: https://blog.x5ff.xyz/blog/async-tests-tokio-rust/
    macro_rules! aw {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
    }

    #[test]
    fn test_usage() {
        assert_eq!(usage(), ());
    }

    #[test]
    fn test_help() {
        assert_eq!(help(), ());
    }

    #[test]
    fn test_manual() {
        assert_eq!(manual(), ());
    }

    #[test]
    fn test_readme() {
        assert_eq!(aw!(readme()), ());
    }

    #[test]
    fn test_version() {
        assert_eq!(version(Output::Text), ());
        assert_eq!(version(Output::Json), ());
    }

    #[test]
    fn test_version_check() {
        assert_eq!(version_check(), ());
    }

    #[test]
    fn test_contribute() {
        assert_eq!(contribute(), ());
    }
}
