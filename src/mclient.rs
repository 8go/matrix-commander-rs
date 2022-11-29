//
// https://www.github.com/8go/matrix-commander-rs
// mclient.rs
//

//! Module that bundles code together that uses the `matrix-sdk` API.
//! Primarily the matrix_sdk::Client API
//! (see <https://docs.rs/matrix-sdk/latest/matrix_sdk/struct.Client.html>).
//! This module implements the matrix-sdk-based portions of the primitives like
//! logging in, logging out, verifying, sending messages, sending files, etc.
//! It excludes receiving and listening (see listen.rs).

use atty::Stream;
// use json::stringify;
use mime::Mime;
use std::borrow::Cow;
use std::io::{self, Read, Write};
// use std::env;
use std::fs;
use std::fs::File;
// use std::ops::Deref;
// use std::path::Path;
use std::path::PathBuf;
use tracing::{debug, error, info, warn};
// use thiserror::Error;
// use directories::ProjectDirs;
// use serde::{Deserialize, Serialize};
//use serde_json::Result;
use url::Url;

use matrix_sdk::{
    attachment::AttachmentConfig,
    config::{RequestConfig, StoreConfig, SyncSettings},
    instant::Duration,
    media::{MediaFormat, MediaRequest},
    room,
    room::{Room, RoomMember},
    ruma::{
        api::client::room::create_room::v3::Request as CreateRoomRequest,
        api::client::room::create_room::v3::RoomPreset,
        api::client::room::Visibility,
        api::client::uiaa,
        events::room::encryption::RoomEncryptionEventContent,
        // OwnedRoomOrAliasId, OwnedServerName,
        // device_id,
        events::room::member::SyncRoomMemberEvent,
        // events::room::message::SyncRoomMessageEvent,
        events::room::message::{
            EmoteMessageEventContent,
            // FileMessageEventContent,
            MessageType,
            NoticeMessageEventContent,
            // OriginalRoomMessageEvent, OriginalSyncRoomMessageEvent,
            // RedactedRoomMessageEventContent, RoomMessageEvent,
            // OriginalSyncRoomEncryptedEvent,
            // RedactedSyncRoomMessageEvent,
            RoomMessageEventContent,
            // SyncRoomMessageEvent,
            TextMessageEventContent,
        },
        events::room::name::SyncRoomNameEvent,
        events::room::power_levels::SyncRoomPowerLevelsEvent,
        events::room::topic::SyncRoomTopicEvent,
        events::room::MediaSource,
        events::AnyInitialStateEvent,
        events::EmptyStateKey,
        events::InitialStateEvent,
        // events::OriginalMessageLikeEvent,
        serde::Raw,
        EventEncryptionAlgorithm,
        // MxcUri,
        // DeviceId,
        // room_id, session_id, user_id,
        OwnedDeviceId,
        OwnedMxcUri,
        OwnedRoomAliasId,
        OwnedRoomId,
        // UInt,
        OwnedUserId,
        RoomAliasId,
        RoomId,
        UserId,
    },
    Client,
};

// from main.rs
use crate::{credentials_exist, get_password, Args, Credentials, Error, Listen, Output, Sync};

// import verification code
#[path = "emoji_verify.rs"]
mod emoji_verify;

/// Convert String to Option with '' being converted to None
fn to_opt(s: &str) -> Option<&str> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Replace '*' in room id list with all rooms the user knows about (joined, left, invited, etc.)
pub(crate) fn replace_star_with_rooms(client: &Client, vecstr: &mut Vec<String>) {
    let blen = vecstr.len();
    vecstr.retain(|x| x.trim() != "*");
    let alen = vecstr.len();
    if blen == alen {
        return;
    }
    for r in client.rooms() {
        vecstr.push(r.room_id().to_string());
    }
}

/// Convert partial room ids, partial room aliases, room aliases to
/// full room ids.
/// !irywieryiwre => !irywieryiwre:matrix.server.com
/// john => !irywieryiwre:matrix.server.com
/// #john => !irywieryiwre:matrix.server.com
/// #john:matrix.server.com => !irywieryiwre:matrix.server.com
pub(crate) async fn convert_to_full_room_ids(
    client: &Client,
    vecstr: &mut Vec<String>,
    default_host: &str,
) {
    vecstr.retain(|x| !x.trim().is_empty());
    for el in vecstr {
        el.retain(|c| !c.is_whitespace());
        if el.starts_with('@') {
            error!("This room alias or id {:?} starts with an at sign. @ are used for user ids, not room id or room aliases. This will fail later.", el);
            continue;
        }
        if !el.starts_with('#') && !el.starts_with('!') {
            el.insert(0, '#');
        }
        if !el.contains(':') {
            el.push(':');
            el.push_str(default_host);
        }
        // now we either full room id or full room alias id
        if el.starts_with('!') {
            continue;
        }
        if el.starts_with('#') {
            match RoomAliasId::parse(el.clone()) {
                Ok(id) => {
                    match client.resolve_room_alias(&id).await {
                        Ok(res) => {
                            el.clear();
                            el.push_str(res.room_id.as_ref());
                        }
                        Err(ref e) => {
                            error!("Error: invalid alias {:?}. resolve_room_alias() returned error {:?}.", el, e);
                            el.clear();
                        }
                    }
                }
                Err(ref e) => {
                    error!("Error: invalid alias {:?}. Error reported is {:?}.", el, e);
                    el.clear();
                }
            }
        }
    }
}

/// Convert partial mxc uris to full mxc uris.
/// SomeStrangeUriKey => "mxc://matrix.server.org/SomeStrangeUriKey"
/// Default_host is a string like "matrix.server.org" or "127.0.0.1"
pub(crate) async fn convert_to_full_mxc_uris(vecstr: &mut Vec<OwnedMxcUri>, default_host: &str) {
    vecstr.retain(|x| !x.as_str().trim().is_empty());
    let num = vecstr.len();
    let mut i = 0;
    while i < num {
        let mut s = vecstr[i].as_str().to_string();
        s.retain(|c| !c.is_whitespace());
        if s.is_empty() {
            debug!("Skipping {:?} because it is empty.", vecstr[i]);
            vecstr[i] = OwnedMxcUri::from("");
            i += 1;
            continue;
        }
        if s.starts_with("mxc://") {
            debug!("Skipping {:?}.", vecstr[i]);
            i += 1;
            continue;
        }
        if s.contains(':') || s.contains('/') {
            error!("This does not seem to be a short MXC URI. Contains : or /. Skipping {:?}. This will likely cause a failure later.", vecstr[i]);
            i += 1;
            continue;
        }
        let mxc = "mxc://".to_owned() + default_host + "/" + &s;
        vecstr[i] = OwnedMxcUri::from(mxc);
        if !vecstr[i].is_valid() {
            error!("This does not seem to be a short MXC URI. Contains : or /. Skipping {:?}. This will likely cause a failure later.", vecstr[i]);
        }
        i += 1;
    }
    vecstr.retain(|x| !x.as_str().trim().is_empty());
}

/// Convert partial user ids to full user ids.
/// john => @john:matrix.server.com
/// @john => @john:matrix.server.com
/// @john:matrix.server.com => @john:matrix.server.com
pub(crate) fn convert_to_full_user_ids(vecstr: &mut Vec<String>, default_host: &str) {
    vecstr.retain(|x| !x.trim().is_empty());
    for el in vecstr {
        el.retain(|c| !c.is_whitespace());
        if el.starts_with('!') {
            error!("This user id {:?} starts with an exclamation mark. ! are used for rooms, not users. This will fail later.", el);
            continue;
        }
        if el.starts_with('#') {
            error!("This user id {:?} starts with a hash tag. # are used for room aliases, not users. This will fail later.", el);
            continue;
        }
        if !el.starts_with('@') {
            el.insert(0, '@');
        }
        if !el.contains(':') {
            el.push(':');
            el.push_str(default_host);
        }
    }
}

/// Convert partial room alias ids to full room alias ids.
/// john => #john:matrix.server.com
/// #john => #john:matrix.server.com
/// #john:matrix.server.com => #john:matrix.server.com
pub(crate) fn convert_to_full_alias_ids(vecstr: &mut Vec<String>, default_host: &str) {
    vecstr.retain(|x| !x.trim().is_empty());
    for el in vecstr {
        el.retain(|c| !c.is_whitespace());
        if el.starts_with('!') {
            warn!("This room alias {:?} starts with an exclamation mark. ! are used for rooms ids, not aliases. This might cause problems later.", el);
            continue;
        }
        if el.starts_with('@') {
            error!("This room alias {:?} starts with an at sign. @ are used for user ids, not aliases. This will fail later.", el);
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

/// Convert full room alias ids to local canonical short room alias ids.
/// #john:matrix.server.com => john
/// #john => john
/// john => john
/// Does NOT remove empty items from vector.
pub(crate) fn convert_to_short_canonical_alias_ids(vecstr: &mut Vec<String>) {
    // don't remove empty ones: vecstr.retain(|x| !x.trim().is_empty());
    // keep '' so we can set the alias to null, e.g. in room_create()
    for el in vecstr {
        el.retain(|c| !c.is_whitespace());
        if el.starts_with('!') {
            warn!("This room alias {:?} starts with an exclamation mark. ! are used for rooms ids, not aliases. This might cause problems later.", el);
            continue;
        }
        if el.starts_with('#') {
            el.remove(0);
        }
        if el.contains(':') {
            match el.find(':') {
                None => (),
                Some(i) => el.truncate(i),
            }
        }
    }
}

/// Constructor for Credentials.
pub(crate) fn restore_credentials(ap: &Args) -> Result<Credentials, Error> {
    if ap.credentials.is_file() {
        let credentials = Credentials::load(&ap.credentials)?;
        debug!("restore_credentials: credentials are {:?}", &credentials);
        Ok(credentials)
    } else {
        Err(Error::NoCredentialsFound)
    }
}

/// Constructor for matrix-sdk async Client, based on restore_login().
pub(crate) async fn restore_login(credentials: &Credentials, ap: &Args) -> Result<Client, Error> {
    let clihomeserver = ap.homeserver.clone();
    let homeserver = clihomeserver.unwrap_or_else(|| credentials.homeserver.clone());
    info!(
        "restoring device with device_id = {:?} on homeserver {:?}.",
        &credentials.device_id, &homeserver
    );
    let session: matrix_sdk::Session = credentials.clone().into();
    let client = create_client(&homeserver, ap).await?;
    client.restore_login(session).await?;
    debug!("restore_login returned successfully. Logged in now.");
    if ap.listen == Listen::Never {
        sync_once(&client, ap.timeout, ap.sync).await?;
    } else {
        info!("Skipping sync due to --listen");
    }
    Ok(client)
}

/// Constructor for matrix-sdk async Client, based on login_username().
pub(crate) async fn login<'a>(
    ap: &'a mut Args,
    homeserver: &Url,
    username: &str,
    password: &str,
    device: &str,
    room_default: &str,
) -> Result<(Client, Credentials), Error> {
    let client = create_client(homeserver, ap).await?;
    debug!("About to call login_username()");
    let response = client
        .login_username(&username, password)
        .initial_device_display_name(device)
        .send()
        .await;
    debug!("Called login_username()");

    match response {
        Ok(n) => debug!("login_username() successful with response {:?}.", n),
        Err(e) => {
            error!("Error: {}", e);
            return Err(Error::LoginFailed);
        }
    }
    let session = client
        .session()
        .expect("error: client not logged in correctly. No session.");
    info!("device id = {}", session.device_id);
    info!("credentials file = {:?}", ap.credentials);

    let credentials = Credentials::new(
        homeserver.clone(),
        session.user_id.clone(),
        session.access_token.clone(),
        session.device_id.clone(),
        room_default.to_string(),
        session.refresh_token,
    );
    credentials.save(&ap.credentials)?;
    info!("Skipping sync due to --listen");
    Ok((client, credentials))
}

/// Prepares a client that can then be used for actual login.
/// Configures the matrix-sdk async Client.
async fn create_client(homeserver: &Url, ap: &Args) -> Result<Client, Error> {
    // The location to save files to
    let sledhome = &ap.store;
    info!("Using sled store {:?}", &sledhome);
    // let builder = if let Some(proxy) = cli.proxy { builder.proxy(proxy) } else { builder };
    let builder = Client::builder()
        .homeserver_url(homeserver)
        .store_config(StoreConfig::new())
        .request_config(
            RequestConfig::new()
                .timeout(Duration::from_secs(ap.timeout))
                .retry_timeout(Duration::from_secs(ap.timeout)),
        );
    let client = builder
        .sled_store(sledhome, None)
        .expect("error: cannot add sled store to ClientBuilder.")
        .build()
        .await
        .expect("error: ClientBuilder build failed."); // no password for sled!
    Ok(client)
}

/// Does emoji verification
pub(crate) async fn verify(client: &Client) -> Result<(), Error> {
    info!("Client logged in: {}", client.logged_in());
    info!("Client access token used: {:?}", client.access_token());
    emoji_verify::sync(client).await?; // wait in sync for other party to initiate emoji verify
    Ok(())
}

/// Logs out, destroying the device and removing credentials file
pub(crate) async fn logout(client: &Client, ap: &Args) -> Result<(), Error> {
    debug!("Logout on client");
    logout_server(client, ap).await?;
    logout_local(ap)
}

/// Only logs out locally, doesn't go to server.
pub(crate) fn logout_local(ap: &Args) -> Result<(), Error> {
    if credentials_exist(ap) {
        match fs::remove_file(&ap.credentials) {
            Ok(()) => info!("Credentials file successfully remove {:?}", &ap.credentials),
            Err(e) => error!(
                "Error: credentials file not removed. {:?} {:?}",
                &ap.credentials, e
            ),
        }
    } else {
        warn!("Credentials file does not exist {:?}", &ap.credentials)
    }
    match fs::remove_dir_all(&ap.store) {
        Ok(()) => info!("Sled directory successfully remove {:?}", &ap.store),
        Err(e) => error!("Error: Sled directory not removed. {:?} {:?}", &ap.store, e),
    }
    Ok(())
}

/// Only logs out from server, no local changes.
pub(crate) async fn logout_server(client: &Client, ap: &Args) -> Result<(), Error> {
    if ap.logout.is_me() {
        match client.logout().await {
            Ok(n) => info!("Logout sent to server {:?}", n),
            Err(e) => error!(
                "Error: Server logout failed but we remove local device id anyway. {:?}",
                e
            ),
        }
    }
    if ap.logout.is_all() {
        debug!("Did nothing on server side. All devices should have been deleted already. Check the log a few lines up.");
    }
    Ok(())
}

// Todo: when is this sync() really necessary? send seems to work without, listen do not need it, devices does not need it but forces it to consume msgs, ...
/// Utility function to synchronize once.
pub(crate) async fn sync_once(client: &Client, timeout: u64, stype: Sync) -> Result<(), Error> {
    debug!("value of sync in sync_once() is {:?}", stype);
    if stype.is_off() {
        info!("syncing is turned off. No syncing.");
    }
    if stype.is_full() {
        info!("syncing once, timeout set to {} seconds ...", timeout);
        client
            .sync_once(SyncSettings::new().timeout(Duration::new(timeout, 0)))
            .await?;
        info!("sync completed");
    }
    Ok(())
}

/*pub(crate) fn room(&self, room_id: &RoomId) -> Result<room::Room> {
    self.get_room(room_id).ok_or(Error::InvalidRoom)
}*/

/*pub(crate) fn invited_room(&self, room_id: &RoomId) -> Result<room::Invited> {
    self.get_invited_room(room_id).ok_or(Error::InvalidRoom)
}*/

// pub(crate) fn joined_room(client: Client, room_id: &RoomId) -> Result<room::Joined> {
//     client.get_joined_room(room_id).ok_or(Error::InvalidRoom)
// }

/*pub(crate) fn left_room(&self, room_id: &RoomId) -> Result<room::Left> {
    self.get_left_room(room_id).ok_or(Error::InvalidRoom)
}*/

/// Print list of devices of the current user.
pub(crate) async fn devices(client: &Client, output: Output) -> Result<(), Error> {
    debug!("Devices on server");
    let response = client.devices().await?;
    for device in response.devices {
        match output {
            Output::Text => println!(
                "Device: {} {}",
                device.device_id,
                device.display_name.as_deref().unwrap_or("")
            ),
            Output::JsonSpec => (),
            _ => println!(
                "{{\"device_id\": {:?}, \"display_name\": {:?}}}",
                device.device_id,
                device.display_name.as_deref().unwrap_or("")
            ),
        }
    }
    Ok(())
}

/// Write the avatar of the current user to a file.
pub(crate) async fn get_avatar(
    client: &Client,
    path: &PathBuf,
    _output: Output,
) -> Result<(), Error> {
    debug!("Get avatar from server");
    if let Ok(Some(avatar)) = client.account().get_avatar(MediaFormat::File).await {
        match std::fs::write(path, avatar) {
            Ok(_) => {
                debug!("Avatar saved successfully");
                Ok(())
            }
            Err(e) => Err(Error::IO(e)),
        }
    } else {
        Err(Error::GetAvatarFailed)
    }
}

/// Get the avatar MXC URI of the current user.
pub(crate) async fn get_avatar_url(client: &Client, output: Output) -> Result<(), Error> {
    debug!("Get avatar MXC from server");
    if let Ok(Some(mxc_uri)) = client.account().get_avatar_url().await {
        debug!(
            "Avatar MXC URI obtained successfully. MXC_URI is {:?}",
            mxc_uri
        );
        print_json(&json::object!(avatar_mxc_uri: mxc_uri.to_string()), output);
        Ok(())
    } else {
        Err(Error::GetAvatarUrlFailed)
    }
}

/// Read the avatar from a file and send it to server to be used as avatar of the current user.
pub(crate) async fn set_avatar(
    client: &Client,
    path: &PathBuf,
    output: Output,
) -> Result<(), Error> {
    debug!("Upload avatar to server");
    let image = match fs::read(path) {
        Ok(image) => {
            debug!("Avatar file read successfully");
            image
        }
        Err(e) => return Err(Error::IO(e)),
    };
    if let Ok(mxc_uri) = client
        .account()
        .upload_avatar(
            &mime_guess::from_path(path).first_or(mime::IMAGE_PNG),
            &image,
        )
        .await
    {
        debug!(
            "Avatar file uploaded successfully. MXC_URI is {:?}",
            mxc_uri
        );
        print_json(
            &json::object!(filename: path.to_str(), avatar_mxc_uri: mxc_uri.to_string()),
            output,
        );
        Ok(())
    } else {
        Err(Error::SetAvatarFailed)
    }
}

/// Send new MXC URI to server to be used as avatar of the current user.
pub(crate) async fn set_avatar_url(
    client: &Client,
    mxc_uri: &OwnedMxcUri,
    _output: Output,
) -> Result<(), Error> {
    debug!("Upload avatar MXC URI to server");
    if let Ok(_) = client.account().set_avatar_url(Some(mxc_uri)).await {
        debug!("Avatar file uploaded successfully.",);
        Ok(())
    } else {
        Err(Error::SetAvatarUrlFailed)
    }
}

/// Remove any MXC URI on server which are used as avatar of the current user.
/// In other words, remove the avatar from the matrix-commander-rs user.
pub(crate) async fn unset_avatar_url(client: &Client, _output: Output) -> Result<(), Error> {
    debug!("Remove avatar MXC URI on server");
    if let Ok(_) = client.account().set_avatar_url(None).await {
        debug!("Avatar removed successfully.",);
        Ok(())
    } else {
        Err(Error::UnsetAvatarUrlFailed)
    }
}

/// Get display name of the current user.
pub(crate) async fn get_display_name(client: &Client, output: Output) -> Result<(), Error> {
    debug!("Get display name from server");
    if let Ok(Some(name)) = client.account().get_display_name().await {
        debug!(
            "Display name obtained successfully. Display name is {:?}",
            name
        );
        print_json(&json::object!(display_name: name), output);
        Ok(())
    } else {
        Err(Error::GetDisplaynameFailed)
    }
}

/// Set display name of the current user.
pub(crate) async fn set_display_name(
    client: &Client,
    name: &String,
    _output: Output,
) -> Result<(), Error> {
    debug!("Set display name of current user");
    if let Ok(_) = client.account().set_display_name(Some(name)).await {
        debug!("Display name set successfully.",);
        Ok(())
    } else {
        Err(Error::SetDisplaynameFailed)
    }
}

/// Get profile of the current user.
pub(crate) async fn get_profile(client: &Client, output: Output) -> Result<(), Error> {
    debug!("Get profile from server");
    if let Ok(profile) = client.account().get_profile().await {
        debug!("Profile successfully. Profile {:?}", profile);
        print_json(
            &json::object!(display_name: profile.displayname, avatar_url: profile.avatar_url.as_ref().map(|x| x.as_str())),
            output,
        );
        Ok(())
    } else {
        Err(Error::GetProfileFailed)
    }
}

/// Get room info for a list of rooms.
/// Includes items such as room id, room display name, room alias, and room topic.
pub(crate) async fn get_room_info(
    client: &Client,
    rooms: &[String],
    output: Output,
) -> Result<(), Error> {
    debug!("Getting room info");
    for (i, roomstr) in rooms.iter().enumerate() {
        debug!("Room number {} with room id {}", i, roomstr);
        let room_id = match RoomId::parse(roomstr) {
            Ok(ref inner) => inner.clone(),
            Err(ref e) => {
                error!("Invalid room id: {:?} {:?}", roomstr, e);
                continue;
            }
        };
        let room = client.get_room(&room_id).ok_or(Error::InvalidRoom)?;
        match output {
            Output::Text => println!(
                "{}    {}    {}    {}",
                room_id,
                room.name().unwrap_or_default(), // alternatively: room.display_name().await.ok().unwrap(),
                match room.canonical_alias() {
                    Some(inner) => inner.to_string(),
                    _ => "".to_string(),
                },
                room.topic().unwrap_or_default(),
                // user_id of room creator,
                // encrypted boolean
            ),
            Output::JsonSpec => (),
            _ => println!(
                "{{\"room_id\": {:?}, \"display_name\": {:?}, \"alias\": {:?}, \"topic\": {:?}}}",
                room_id,
                room.name().unwrap_or_default(), // alternatively: room.display_name().await.ok().unwrap(),
                match room.canonical_alias() {
                    Some(inner) => inner.to_string(),
                    _ => "".to_string(),
                },
                room.topic().unwrap_or_default(),
                // user_id of room creator,
                // encrypted boolean
            ),
        };
    }
    Ok(())
}

/// Utility function to print JSON object as JSON or as plain text
pub(crate) fn print_json(json_data: &json::JsonValue, output: Output) {
    debug!("{:?}", json_data);
    match output {
        Output::Text => {
            let mut first = true;
            for (key, val) in json_data.entries() {
                if first {
                    first = false;
                } else {
                    print!("    ");
                }
                print!("{}:", key);
                if val.is_object() {
                    // if it is an object, check recursively
                    print_json(val, output);
                } else if val.is_boolean() {
                    print!("    {}", val);
                } else if val.is_null() {
                    print!("    "); // print nothing
                } else if val.is_string() {
                    print!("    {}", val);
                } else if val.is_number() {
                    print!("    {}", val);
                } else if val.is_array() {
                    print!("    [{}]", val);
                }
            }
            println!();
        }
        Output::JsonSpec => (),
        _ => {
            println!("{}", json_data.dump(),);
        }
    }
}

/// Utility function to print Common room info
pub(crate) fn print_common_room(room: &room::Common, output: Output) {
    debug!("common room: {:?}", room);
    match output {
        Output::Text => println!(
            "Room:    {:?}    {}    {:?}    {}    {:?}    {:?}",
            room.room_id(),
            serde_json::to_string(&room.room_type()).unwrap_or_else(|_| r#""""#.to_string()), // serialize, empty string as default
            room.canonical_alias()
                .map_or(r#""#.to_string(), |v| v.to_string()),
            serde_json::to_string(&room.alt_aliases()).unwrap_or_else(|_| r#"[]"#.to_string()), // serialize, empty array as default
            room.name().unwrap_or_default(),
            room.topic().unwrap_or_default(),
            // room.display_name() // this call would go to the server
        ),
        Output::JsonSpec => (),
        _ => {
            println!(
                            "{{\"room_id\": {:?}, \"room_type\": {}, \"canonical_alias\": {:?}, \"alt_aliases\": {}, \"name\": {:?}, \"topic\": {:?}}}",
                            room.room_id(),
                            serde_json::to_string(&room.room_type()).unwrap_or_else(|_| r#""""#.to_string()), // serialize, empty string as default
                            room.canonical_alias().map_or(r#""#.to_string(),|v|v.to_string()),
                            serde_json::to_string(&room.alt_aliases()).unwrap_or_else(|_| r#"[]"#.to_string()), // serialize, empty array as default
                            room.name().unwrap_or_default(),
                            room.topic().unwrap_or_default(),
                        );
        }
    }
}

/// Print list of rooms of a given type (invited, joined, left, all) of the current user.
pub(crate) fn print_rooms(
    client: &Client,
    rooms: Option<matrix_sdk::RoomType>, // None is the default and prints all 3 types of rooms
    output: Output,
) -> Result<(), Error> {
    debug!("Rooms (local)");
    match rooms {
        None => {
            // ALL rooms, default
            for r in client.rooms() {
                // *r changes type to Common, so &(*r), or just &r for short
                print_common_room(&r, output);
            }
        }
        Some(matrix_sdk::RoomType::Invited) => {
            for r in client.invited_rooms() {
                print_common_room(&r, output);
            }
        }
        Some(matrix_sdk::RoomType::Joined) => {
            for r in client.joined_rooms() {
                print_common_room(&r, output);
            }
        }
        Some(matrix_sdk::RoomType::Left) => {
            for r in client.left_rooms() {
                print_common_room(&r, output);
            }
        }
    };
    Ok(())
}

/// Print list of all rooms (invited, joined, left) of the current user.
pub(crate) async fn rooms(client: &Client, output: Output) -> Result<(), Error> {
    debug!("Rooms (local)");
    print_rooms(client, None, output)
}

/// Print list of all invited rooms (not joined, not left) of the current user.
pub(crate) async fn invited_rooms(client: &Client, output: Output) -> Result<(), Error> {
    debug!("Invited_rooms (local)");
    print_rooms(client, Some(matrix_sdk::RoomType::Invited), output)
}

/// Print list of all joined rooms (not invited, not left) of the current user.
pub(crate) async fn joined_rooms(client: &Client, output: Output) -> Result<(), Error> {
    debug!("Joined_rooms (local)");
    print_rooms(client, Some(matrix_sdk::RoomType::Joined), output)
}

/// Print list of all left rooms (not invited, not joined) of the current user.
pub(crate) async fn left_rooms(client: &Client, output: Output) -> Result<(), Error> {
    debug!("Left_rooms (local)");
    print_rooms(client, Some(matrix_sdk::RoomType::Left), output)
}

/// Create rooms, either noemal room or DM room:
/// For normal room, create one room for each alias name in the list.
/// For DM room, create one DM room for each user name in the list.
/// Alias name can be empty, i.e. ''.
/// If and when available set the room name from the name list.
/// If and when available set the topic name from the topic list.
/// As output it lists/prints the newly generated room ids and and the corresponding room aliases.
pub(crate) async fn room_create(
    client: &Client,
    is_dm: bool,             //is DM room
    is_encrypted: bool,      // share we create an encrypted room or not
    users: &[String],        // users, only useful for DM rooms
    room_aliases: &[String], // list of simple alias names like 'SomeAlias', not full aliases
    names: &[String],        // list of room names, optional
    room_topics: &[String],  // list of room topics, optional
    output: Output,          // how to format output
) -> Result<(), Error> {
    debug!("Creating room(s)");
    debug!(
        "Creating room(s): dm {:?}, u {:?}, a {:?}, n {:?}, t {:?}",
        is_dm, users, room_aliases, names, room_topics
    );
    // num...the number of rooms we are going to create
    let num = if is_dm {
        users.len()
    } else {
        room_aliases.len()
    };
    let mut users2 = Vec::new();
    let mut aliases2 = room_aliases.to_owned();
    let mut names2 = names.to_owned();
    let mut topics2 = room_topics.to_owned();
    if is_dm {
        aliases2.resize(num, "".to_string());
        users2.extend_from_slice(users);
    } else {
        users2.resize(num, "".to_string());
    }
    convert_to_short_canonical_alias_ids(&mut aliases2);
    names2.resize(num, "".to_string());
    topics2.resize(num, "".to_string());
    // all 4 vectors are now at least 'num' long; '' represents None
    let mut i = 0usize;
    let mut err_count = 0usize;
    debug!(
        "Creating room(s): dm {:?}, u {:?}, a {:?}, n {:?}, t {:?}, num {}",
        is_dm, users2, aliases2, names2, topics2, num
    );
    while i < num {
        debug!(
            "In position {} we have user {:?}, alias name {:?}, room name {:?}, room topic {:?}.",
            i, users2[i], aliases2[i], names2[i], topics2[i]
        );

        let mut request = CreateRoomRequest::new();
        let mut initstateevvec: Vec<Raw<AnyInitialStateEvent>> = vec![];
        if is_encrypted {
            // see: https://docs.rs/ruma/0.7.4/ruma/api/client/room/create_room/v3/struct.Request.html
            // pub struct Request<'a> {
            //     pub creation_content: Option<Raw<CreationContent>>,
            //     pub initial_state: &'a [Raw<AnyInitialStateEvent>],
            //     pub invite: &'a [OwnedUserId],
            //     pub invite_3pid: &'a [Invite3pid<'a>],
            //     pub is_direct: bool,
            //     pub name: Option<&'a str>,
            //     pub power_level_content_override: Option<Raw<RoomPowerLevelsEventContent>>,
            //     pub preset: Option<RoomPreset>,
            //     pub room_alias_name: Option<&'a str>,
            //     pub room_version: Option<&'a RoomVersionId>,
            //     pub topic: Option<&'a str>,
            //     pub visibility: Visibility,  }
            let content =
                RoomEncryptionEventContent::new(EventEncryptionAlgorithm::MegolmV1AesSha2);
            let initstateev: InitialStateEvent<RoomEncryptionEventContent>;
            initstateev = InitialStateEvent {
                content,
                state_key: EmptyStateKey,
            };
            let rawinitstateev = Raw::new(&initstateev)?;
            // let anyinitstateev: AnyInitialStateEvent =
            //     matrix_sdk::ruma::events::AnyInitialStateEvent::RoomEncryption(initstateev);
            // todo: better alternative? let anyinitstateev2: AnyInitialStateEvent = AnyInitialStateEvent::from(initstateev);

            let rawanyinitstateev: Raw<AnyInitialStateEvent> = rawinitstateev.cast();
            initstateevvec.push(rawanyinitstateev);
            request.initial_state = &initstateevvec;
        }

        request.name = to_opt(&names2[i]);
        request.room_alias_name = to_opt(&aliases2[i]);
        request.topic = to_opt(&topics2[i]);
        request.is_direct = is_dm;
        let usr: OwnedUserId;
        // Visibility defaults to "Private" by matrix-sdk API, so "Private" for both normal rooms and DM rooms.
        let vis = Visibility::Private;
        let mut invites = vec![];
        if is_dm {
            usr = match UserId::parse(<std::string::String as AsRef<str>>::as_ref(&users2[i])) {
                Ok(u) => u,
                Err(ref e) => {
                    err_count += 1;
                    i += 1;
                    error!("Error: create_room failed, because user for DM is not valid, reported error {:?}.", e);
                    continue;
                }
            };
            invites.push(usr);
            request.invite = &invites;
            request.visibility = vis.clone();
            request.preset = Some(RoomPreset::PrivateChat);
        }
        match client.create_room(request).await {
            Ok(response) => {
                debug!("create_room succeeded, result is {:?}.", response);
                print_json(
                    &json::object!(
                        room_id: response.room_id.to_string(),
                        alias: to_opt(&aliases2[i]),
                        name: to_opt(&names2[i]),
                        topic: to_opt(&topics2[i]),
                        invited: <std::string::String as AsRef<str>>::as_ref(&users2[i]),
                        direct: is_dm,
                        encrypted: is_encrypted,
                        visibility: vis.to_string()
                    ),
                    output,
                );
                // room_enable_encryption(): no longer needed, already done by setting request.initial_state
            }
            Err(ref e) => {
                err_count += 1;
                error!("Error: create_room failed, reported error {:?}.", e);
            }
        }
        i += 1;
    }
    if err_count != 0 {
        Err(Error::CreateRoomFailed)
    } else {
        Ok(())
    }
}

/// Leave room(s), leave all the rooms whose ids are given in the list.
/// There is no output to stdout except debug and logging information.
/// If successful nothing will be output.
pub(crate) async fn room_leave(
    client: &Client,
    room_ids: &[String], // list of room ids
    _output: Output,     // how to format output, currently no output
) -> Result<(), Error> {
    debug!("Leaving room(s)");
    let mut err_count = 0u32;
    // convert Vec of strings into a slice of array of OwnedRoomIds
    let mut roomids: Vec<OwnedRoomId> = Vec::new();
    for room_id in room_ids {
        roomids.push(match RoomId::parse(room_id.clone()) {
            Ok(id) => id,
            Err(ref e) => {
                error!(
                    "Error: invalid room id {:?}. Error reported is {:?}.",
                    room_id, e
                );
                err_count += 1;
                continue;
            }
        });
    }
    for (i, id) in roomids.iter().enumerate() {
        debug!("In position {} we have room id {:?}.", i, id,);
        let jroomopt = client.get_joined_room(id);
        match jroomopt {
            Some(jroom) => match jroom.leave().await {
                Ok(_) => {
                    info!("Left room {:?} successfully.", id);
                    // Todo: does this work? Does not seem to work.
                    jroom.clone_info().mark_as_left();
                    // Todo: starting v0.7 this sync() will no longer be necessary
                    client
                        .sync_once(SyncSettings::new().timeout(Duration::new(10, 0)))
                        .await?; //todo: remove this it did not fix the problem.
                }
                Err(ref e) => {
                    error!("Error: leave() returned error {:?}.", e);
                    err_count += 1;
                }
            },
            None => {
                error!("Error: get_joined_room() returned error. Are you member of this room?");
                err_count += 1;
            }
        }
    }
    if err_count != 0 {
        Err(Error::LeaveRoomFailed)
    } else {
        Ok(())
    }
}

/// Forget room(s), forget all the rooms whose ids are given in the list.
/// Before you can forget a room you must leave it first.
/// There is no output to stdout except debug and logging information.
/// If successful nothing will be output.
pub(crate) async fn room_forget(
    client: &Client,
    room_ids: &[String], // list of room ids
    _output: Output,     // how to format output, currently no output
) -> Result<(), Error> {
    debug!("Forgetting room(s)");
    let mut err_count = 0u32;
    debug!("All rooms of the default user: {:?}.", client.rooms());
    // convert Vec of strings into a slice of array of OwnedRoomIds
    let mut roomids: Vec<OwnedRoomId> = Vec::new();
    for room_id in room_ids {
        roomids.push(match RoomId::parse(room_id.clone()) {
            Ok(id) => id,
            Err(ref e) => {
                error!(
                    "Error: invalid room id {:?}. Error reported is {:?}.",
                    room_id, e
                );
                err_count += 1;
                continue;
            }
        });
    }
    for (i, id) in roomids.iter().enumerate() {
        debug!("In position {} we have room id {:?}.", i, id,);
        let jroomopt = client.get_left_room(id);
        match jroomopt {
            Some(jroom) => match jroom.forget().await {
                Ok(_) => {
                    info!("Forgot room {:?} successfully.", id);
                }
                Err(ref e) => {
                    error!("Error: forget() returned error {:?}.", e);
                    err_count += 1;
                }
            },
            None => {
                error!("Error: get_left_room() returned error. Have you been a member of this room? Have you left this room before? Leave the room before forgetting it.");
                err_count += 1;
            }
        }
    }
    if err_count != 0 {
        Err(Error::ForgetRoomFailed)
    } else {
        Ok(())
    }
}

/// Invite user(s) into room(s).
/// There is no output to stdout except debug and logging information.
/// If successful nothing will be output.
pub(crate) async fn room_invite(
    client: &Client,
    room_ids: &[String], // list of room ids
    user_ids: &[String], // list of user ids
    _output: Output,     // how to format output, currently no output
) -> Result<(), Error> {
    debug!(
        "Inviting user(s) to room(s): users={:?}, rooms={:?}",
        user_ids, room_ids
    );
    let mut err_count = 0u32;
    // convert Vec of strings into a slice of array of OwnedRoomIds
    let mut roomids: Vec<OwnedRoomId> = Vec::new();
    for room_id in room_ids {
        roomids.push(
            match RoomId::parse(<std::string::String as AsRef<str>>::as_ref(room_id)) {
                Ok(id) => id,
                Err(ref e) => {
                    error!(
                        "Error: invalid room id {:?}. Error reported is {:?}.",
                        room_id, e
                    );
                    err_count += 1;
                    continue;
                }
            },
        );
    }
    // convert Vec of strings into a slice of array of OwnedUserIds
    let mut userids: Vec<OwnedUserId> = Vec::new();
    for user_id in user_ids {
        userids.push(
            match UserId::parse(<std::string::String as AsRef<str>>::as_ref(user_id)) {
                Ok(id) => id,
                Err(ref e) => {
                    error!(
                        "Error: invalid user id {:?}. Error reported is {:?}.",
                        user_id, e
                    );
                    err_count += 1;
                    continue;
                }
            },
        );
    }
    if roomids.is_empty() || userids.is_empty() {
        if roomids.is_empty() {
            error!("No valid rooms. Cannot invite anyone. Giving up.")
        } else {
            error!("No valid users. Cannot invite anyone. Giving up.")
        }
        return Err(Error::InviteRoomFailed);
    }
    for (i, id) in roomids.iter().enumerate() {
        debug!("In position {} we have room id {:?}.", i, id,);
        let jroomopt = client.get_joined_room(id);
        match jroomopt {
            Some(jroom) => {
                for u in &userids {
                    match jroom.invite_user_by_id(u).await {
                        Ok(_) => {
                            info!("Invited user {:?} to room {:?} successfully.", u, id);
                        }
                        Err(ref e) => {
                            error!("Error: failed to invited user {:?} to room {:?}. invite_user_by_id() returned error {:?}.", u, id, e);
                            err_count += 1;
                        }
                    }
                }
            }
            None => {
                error!("Error: get_joined_room() returned error. Are you a member of this room ({:?})? Join the room before inviting others to it.", id);
                err_count += 1;
            }
        }
    }
    if err_count != 0 {
        Err(Error::InviteRoomFailed)
    } else {
        Ok(())
    }
}

/// Join itself into room(s).
/// There is no output to stdout except debug and logging information.
/// If successful nothing will be output.
pub(crate) async fn room_join(
    client: &Client,
    room_ids: &[String], // list of room ids
    _output: Output,     // how to format output, currently no output
) -> Result<(), Error> {
    debug!("Joining itself into room(s): rooms={:?}", room_ids);
    let mut err_count = 0u32;
    // convert Vec of strings into a slice of array of OwnedRoomIds
    let mut roomids: Vec<OwnedRoomId> = Vec::new();
    for room_id in room_ids {
        roomids.push(
            match RoomId::parse(<std::string::String as AsRef<str>>::as_ref(room_id)) {
                Ok(id) => id,
                Err(ref e) => {
                    error!(
                        "Error: invalid room id {:?}. Error reported is {:?}.",
                        room_id, e
                    );
                    err_count += 1;
                    continue;
                }
            },
        );
    }
    if roomids.is_empty() {
        error!("No valid rooms. Cannot join any room. Giving up.");
        return Err(Error::JoinRoomFailed);
    }
    for (i, id) in roomids.iter().enumerate() {
        debug!("In position {} we have room id {:?}.", i, id,);
        match client.join_room_by_id(id).await {
            Ok(_) => {
                info!("Joined room {:?} successfully.", id);
            }
            Err(ref e) => {
                error!(
                    "Error: failed to room {:?}. join_room_by_id() returned error {:?}.",
                    id, e
                );
                err_count += 1;
            }
        }
    }
    if err_count != 0 {
        Err(Error::JoinRoomFailed)
    } else {
        Ok(())
    }
}

/// Ban user(s) from room(s).
/// There is no output to stdout except debug and logging information.
/// If successful nothing will be output.
pub(crate) async fn room_ban(
    client: &Client,
    room_ids: &[String], // list of room ids
    user_ids: &[String], // list of user ids
    _output: Output,     // how to format output, currently no output
) -> Result<(), Error> {
    debug!(
        "Banning user(s) from room(s): users={:?}, rooms={:?}",
        user_ids, room_ids
    );
    let mut err_count = 0u32;
    // convert Vec of strings into a slice of array of OwnedRoomIds
    let mut roomids: Vec<OwnedRoomId> = Vec::new();
    for room_id in room_ids {
        roomids.push(
            match RoomId::parse(<std::string::String as AsRef<str>>::as_ref(room_id)) {
                Ok(id) => id,
                Err(ref e) => {
                    error!(
                        "Error: invalid room id {:?}. Error reported is {:?}.",
                        room_id, e
                    );
                    err_count += 1;
                    continue;
                }
            },
        );
    }
    // convert Vec of strings into a slice of array of OwnedUserIds
    let mut userids: Vec<OwnedUserId> = Vec::new();
    for user_id in user_ids {
        userids.push(
            match UserId::parse(<std::string::String as AsRef<str>>::as_ref(user_id)) {
                Ok(id) => id,
                Err(ref e) => {
                    error!(
                        "Error: invalid user id {:?}. Error reported is {:?}.",
                        user_id, e
                    );
                    err_count += 1;
                    continue;
                }
            },
        );
    }
    if roomids.is_empty() || userids.is_empty() {
        if roomids.is_empty() {
            error!("No valid rooms. Cannot ban anyone. Giving up.")
        } else {
            error!("No valid users. Cannot ban anyone. Giving up.")
        }
        return Err(Error::BanRoomFailed);
    }
    for (i, id) in roomids.iter().enumerate() {
        debug!("In position {} we have room id {:?}.", i, id,);
        let jroomopt = client.get_joined_room(id);
        match jroomopt {
            Some(jroom) => {
                for u in &userids {
                    match jroom.ban_user(u, None).await {
                        Ok(_) => {
                            info!("Banned user {:?} from room {:?} successfully.", u, id);
                        }
                        Err(ref e) => {
                            error!("Error: failed to ban user {:?} from room {:?}. ban_user() returned error {:?}.", u, id, e);
                            err_count += 1;
                        }
                    }
                }
            }
            None => {
                error!("Error: get_joined_room() returned error. Are you a member of this room ({:?})? Join the room before banning others from it.", id);
                err_count += 1;
            }
        }
    }
    if err_count != 0 {
        Err(Error::BanRoomFailed)
    } else {
        Ok(())
    }
}

/// Unbanning user(s) from room(s).
/// There is no output to stdout except debug and logging information.
/// If successful nothing will be output.
pub(crate) async fn room_unban(
    _client: &Client,
    room_ids: &[String], // list of room ids
    user_ids: &[String], // list of user ids
    _output: Output,     // how to format output, currently no output
) -> Result<(), Error> {
    debug!(
        "Unbaning user(s) from room(s): users={:?}, rooms={:?}",
        user_ids, room_ids
    );
    let mut err_count = 0u32;
    error!("unban is currently not supported by the matrix-sdk API. Ignoring this unban request.");
    err_count += 1;
    if err_count != 0 {
        Err(Error::UnbanRoomFailed)
    } else {
        Ok(())
    }
}

/// Kicking user(s) from room(s).
/// There is no output to stdout except debug and logging information.
/// If successful nothing will be output.
pub(crate) async fn room_kick(
    client: &Client,
    room_ids: &[String], // list of room ids
    user_ids: &[String], // list of user ids
    _output: Output,     // how to format output, currently no output
) -> Result<(), Error> {
    debug!(
        "Kicking user(s) from room(s): users={:?}, rooms={:?}",
        user_ids, room_ids
    );
    let mut err_count = 0u32;
    // convert Vec of strings into a slice of array of OwnedRoomIds
    let mut roomids: Vec<OwnedRoomId> = Vec::new();
    for room_id in room_ids {
        roomids.push(
            match RoomId::parse(<std::string::String as AsRef<str>>::as_ref(room_id)) {
                Ok(id) => id,
                Err(ref e) => {
                    error!(
                        "Error: invalid room id {:?}. Error reported is {:?}.",
                        room_id, e
                    );
                    err_count += 1;
                    continue;
                }
            },
        );
    }
    // convert Vec of strings into a slice of array of OwnedUserIds
    let mut userids: Vec<OwnedUserId> = Vec::new();
    for user_id in user_ids {
        userids.push(
            match UserId::parse(<std::string::String as AsRef<str>>::as_ref(user_id)) {
                Ok(id) => id,
                Err(ref e) => {
                    error!(
                        "Error: invalid user id {:?}. Error reported is {:?}.",
                        user_id, e
                    );
                    err_count += 1;
                    continue;
                }
            },
        );
    }
    if roomids.is_empty() || userids.is_empty() {
        if roomids.is_empty() {
            error!("No valid rooms. Cannot kick anyone. Giving up.")
        } else {
            error!("No valid users. Cannot kick anyone. Giving up.")
        }
        return Err(Error::KickRoomFailed);
    }
    for (i, id) in roomids.iter().enumerate() {
        debug!("In position {} we have room id {:?}.", i, id,);
        let jroomopt = client.get_joined_room(id);
        match jroomopt {
            Some(jroom) => {
                for u in &userids {
                    match jroom.kick_user(u, None).await {
                        Ok(_) => {
                            info!("Kicked user {:?} from room {:?} successfully.", u, id);
                        }
                        Err(ref e) => {
                            error!("Error: failed to kick user {:?} from room {:?}. kick_user() returned error {:?}.", u, id, e);
                            err_count += 1;
                        }
                    }
                }
            }
            None => {
                error!("Error: get_joined_room() returned error. Are you a member of this room ({:?})? Join the room before kicking others from it.", id);
                err_count += 1;
            }
        }
    }
    if err_count != 0 {
        Err(Error::KickRoomFailed)
    } else {
        Ok(())
    }
}

/// Utility function to print visibility of a single room
fn print_room_visibility(room_id: &OwnedRoomId, room: &Room, output: Output) {
    match output {
        Output::Text => {
            println!(
                "Room:    {:?}    {:?}",
                room_id,
                if room.is_public() {
                    "public"
                } else {
                    "private"
                },
            )
        }
        Output::JsonSpec => (),
        _ => {
            println!(
                "{{\"room_id\": {:?}, \"public\": {}}}",
                room_id,
                room.is_public()
            );
        }
    }
}

/// Listing visibility (public/private) for all room(s).
/// There will be one line printed per room.
pub(crate) async fn room_get_visibility(
    client: &Client,
    room_ids: &[String], // list of room ids
    output: Output,      // how to format output
) -> Result<(), Error> {
    debug!("Get room visibility for room(s): rooms={:?}", room_ids);
    let mut err_count = 0u32;
    // convert Vec of strings into a slice of array of OwnedRoomIds
    let mut roomids: Vec<OwnedRoomId> = Vec::new();
    for room_id in room_ids {
        roomids.push(
            match RoomId::parse(<std::string::String as AsRef<str>>::as_ref(room_id)) {
                Ok(id) => id,
                Err(ref e) => {
                    error!(
                        "Error: invalid room id {:?}. Error reported is {:?}.",
                        room_id, e
                    );
                    err_count += 1;
                    continue;
                }
            },
        );
    }
    if roomids.is_empty() {
        error!("No valid rooms. Cannot list anything. Giving up.");
        return Err(Error::RoomGetVisibilityFailed);
    }
    for (i, id) in roomids.iter().enumerate() {
        debug!("In position {} we have room id {:?}.", i, id,);
        match client.get_room(id) {
            Some(r) => {
                print_room_visibility(id, &r, output);
            }
            None => {
                error!(
                    "Error: failed to get room {:?}. get_room() returned error no room.",
                    id
                );
                err_count += 1;
            }
        }
    }
    if err_count != 0 {
        Err(Error::RoomGetVisibilityFailed)
    } else {
        Ok(())
    }
}

/// Utility function to print part of the state of a single room
async fn print_room_state(room_id: &OwnedRoomId, room: &Room, output: Output) -> Result<(), Error> {
    // There are around 50 events for rooms
    // See https://docs.rs/ruma/0.7.4/ruma/?search=syncroom
    // We only do 4 as example to start with.
    let room_member_evs: Vec<Raw<SyncRoomMemberEvent>> = room.get_state_events_static().await?;
    let power_levels_ev: Raw<SyncRoomPowerLevelsEvent> = room
        .get_state_event_static()
        .await?
        .ok_or(Error::RoomGetStateFailed)?;
    let name_ev: Raw<SyncRoomNameEvent> = room
        .get_state_event_static()
        .await?
        .ok_or(Error::RoomGetStateFailed)?;
    let topic_ev: Raw<SyncRoomTopicEvent> = room
        .get_state_event_static()
        .await?
        .ok_or(Error::RoomGetStateFailed)?;
    match output {
        Output::Text => {
            print!("Room:    {:?},    SyncRoomMemberEvents: [", room_id);
            let mut first: bool = true;
            for ev in room_member_evs {
                if first {
                    first = false;
                } else {
                    print!(", ");
                }
                print!("\"{:?}\"", ev.deserialize());
            }
            println!(
                "],    SyncRoomTopicEvent: \"{:?}\",    SyncRoomPowerLevelsEvent: \"{:?}\",    SyncRoomNameEvent: \"{:?}\"",
                topic_ev.deserialize(),
                power_levels_ev.deserialize(),
                name_ev.deserialize()
            );
        }
        // Output::JsonSpec => (), // These events should be spec compliant
        _ => {
            print!("{{\"room_id\": {:?}, \"SyncRoomMemberEvents\": [", room_id);
            let mut first: bool = true;
            for ev in room_member_evs {
                if first {
                    first = false;
                } else {
                    print!(", ");
                }
                print!(
                    "{{ {} }}",
                    serde_json::to_string(&ev.deserialize()?)
                        .unwrap_or_else(|_| r#""""#.to_string())
                );
            }
            println!(
                "], \"SyncRoomTopicvent\": {}, \"SyncRoomPowerLevelsEvent\": {}, \"SyncRoomNameEvent\": {}}}",
                serde_json::to_string(&topic_ev.deserialize()?)
                    .unwrap_or_else(|_| r#""""#.to_string()),
                serde_json::to_string(&power_levels_ev.deserialize()?)
                    .unwrap_or_else(|_| r#""""#.to_string()),
                serde_json::to_string(&name_ev.deserialize()?)
                    .unwrap_or_else(|_| r#""""#.to_string()),
            );
        }
    }
    Ok(())
}

/// Listing partial state for all room(s).
/// There will be one line printed per room.
pub(crate) async fn room_get_state(
    client: &Client,
    room_ids: &[String], // list of room ids
    output: Output,      // how to format output
) -> Result<(), Error> {
    debug!("Get room state for room(s): rooms={:?}", room_ids);
    let mut err_count = 0u32;
    // convert Vec of strings into a slice of array of OwnedRoomIds
    let mut roomids: Vec<OwnedRoomId> = Vec::new();
    for room_id in room_ids {
        roomids.push(
            match RoomId::parse(<std::string::String as AsRef<str>>::as_ref(room_id)) {
                Ok(id) => id,
                Err(ref e) => {
                    error!(
                        "Error: invalid room id {:?}. Error reported is {:?}.",
                        room_id, e
                    );
                    err_count += 1;
                    continue;
                }
            },
        );
    }
    if roomids.is_empty() {
        error!("No valid rooms. Cannot list anything. Giving up.");
        return Err(Error::RoomGetStateFailed);
    }
    for (i, id) in roomids.iter().enumerate() {
        debug!("In position {} we have room id {:?}.", i, id,);
        match client.get_room(id) {
            Some(r) => {
                if print_room_state(id, &r, output).await.is_err() {
                    error!("Error: failed to get room state for room {:?}.", id);
                    err_count += 1;
                };
            }
            None => {
                error!(
                    "Error: failed to get room {:?}. get_room() returned error no room.",
                    id
                );
                err_count += 1;
            }
        }
    }
    if err_count != 0 {
        Err(Error::RoomGetStateFailed)
    } else {
        Ok(())
    }
}

/// Utility function to print all members of a single room
fn print_room_members(room_id: &OwnedRoomId, members: &[RoomMember], output: Output) {
    match output {
        Output::Text => {
            for m in members {
                println!(
                    "Room:    {:?}    Member:    {:?}    {:?}    {:?}    {:?}    {:?}    \"{:?}\"",
                    room_id,
                    m.user_id(),
                    m.display_name().as_deref().unwrap_or(""),
                    m.name(),
                    m.avatar_url().as_deref().unwrap_or("".into()),
                    m.power_level(),
                    m.membership(),
                )
            }
        }
        Output::JsonSpec => (),
        _ => {
            let mut first: bool = true;
            print!("{{\"room_id\": {:?}, \"members\": [", room_id);
            for m in members {
                if first {
                    first = false;
                } else {
                    print!(", ");
                }
                print!(
                    "{{\"user_id\": {:?}, \"display_name\": {:?}, \"name\": {:?}, \"avatar_url\": {:?}, \"power_level\": {:?}, \"membership\": \"{:?}\"}}",
                    m.user_id(),
                    m.display_name().as_deref().unwrap_or(""),
                    m.name(),
                    m.avatar_url().as_deref().unwrap_or("".into()),
                    m.power_level(),
                    m.membership(),
                );
            }
            println!("]}}");
        }
    }
}

/// Listing all joined member(s) for all room(s).
/// Does not list all members, e.g. does not list invited members, etc.
/// There will be one line printed per room.
pub(crate) async fn joined_members(
    client: &Client,
    room_ids: &[String], // list of room ids
    output: Output,      // how to format output
) -> Result<(), Error> {
    debug!("Joined members for room(s): rooms={:?}", room_ids);
    let mut err_count = 0u32;
    // convert Vec of strings into a slice of array of OwnedRoomIds
    let mut roomids: Vec<OwnedRoomId> = Vec::new();
    for room_id in room_ids {
        roomids.push(
            match RoomId::parse(<std::string::String as AsRef<str>>::as_ref(room_id)) {
                Ok(id) => id,
                Err(ref e) => {
                    error!(
                        "Error: invalid room id {:?}. Error reported is {:?}.",
                        room_id, e
                    );
                    err_count += 1;
                    continue;
                }
            },
        );
    }
    if roomids.is_empty() {
        error!("No valid rooms. Cannot kick anyone. Giving up.");
        return Err(Error::JoinedMembersFailed);
    }
    for (i, id) in roomids.iter().enumerate() {
        debug!("In position {} we have room id {:?}.", i, id,);
        match client.get_room(id) {
            Some(r) => match r.members().await {
                Ok(ref m) => {
                    debug!("Members of room {:?} are {:?}.", id, m);
                    print_room_members(id, m, output);
                }
                Err(ref e) => {
                    error!(
                        "Error: failed to get members of room {:?}. members() returned error {:?}.",
                        id, e
                    );
                    err_count += 1;
                }
            },
            None => {
                error!(
                    "Error: failed to get room {:?}. get_room() returned error no room.",
                    id
                );
                err_count += 1;
            }
        }
    }
    if err_count != 0 {
        Err(Error::JoinedMembersFailed)
    } else {
        Ok(())
    }
}

/// Get room name(s) based on room alias(es).
pub(crate) async fn room_resolve_alias(
    client: &Client,
    alias_ids: &[String], // list of room aliases
    output: Output,       // how to format output, currently no output
) -> Result<(), Error> {
    debug!("Resolving room alias(es)");
    let mut err_count = 0u32;
    debug!("Aliases given: {:?}.", alias_ids);
    // convert Vec of strings into a slice of array of OwnedRoomAliasIds
    let mut aliasids: Vec<OwnedRoomAliasId> = Vec::new();
    for alias_id in alias_ids {
        aliasids.push(match RoomAliasId::parse(alias_id.clone()) {
            Ok(id) => id,
            Err(ref e) => {
                error!(
                    "Error: invalid alias id {:?}. Error reported is {:?}.",
                    alias_id, e
                );
                continue;
            }
        });
    }
    for (i, id) in aliasids.iter().enumerate() {
        debug!("In position {} we have room alias id {:?}.", i, id,);
        match client.resolve_room_alias(id).await {
            Ok(res) => {
                info!("Resolved room alias {:?} successfully.", id);
                match output {
                    Output::Text => println!("Room: {:?} {:?} {:?}", id, res.room_id, res.servers),
                    Output::JsonSpec => (),
                    _ => println!(
                        "{{\"alias_id\": {:?}, \"room_id\": {:?}, \"servers\": {:?}}}",
                        id, res.room_id, res.servers
                    ),
                }
            }
            Err(ref e) => {
                error!("Error: resolve_room_alias() returned error {:?}.", e);
                err_count += 1;
            }
        }
    }
    if err_count != 0 {
        Err(Error::ResolveRoomAliasFailed)
    } else {
        Ok(())
    }
}

/// Enable encryption for given room(s).
pub(crate) async fn room_enable_encryption(
    client: &Client,
    room_ids: &[String], // list of room ids
    _output: Output,     // how to format output
) -> Result<(), Error> {
    debug!("Enable encryption for room(s): rooms={:?}", room_ids);
    let mut err_count = 0u32;
    // convert Vec of strings into a slice of array of OwnedRoomIds
    let mut roomids: Vec<OwnedRoomId> = Vec::new();
    for room_id in room_ids {
        roomids.push(
            match RoomId::parse(<std::string::String as AsRef<str>>::as_ref(room_id)) {
                Ok(id) => id,
                Err(ref e) => {
                    error!(
                        "Error: invalid room id {:?}. Error reported is {:?}.",
                        room_id, e
                    );
                    err_count += 1;
                    continue;
                }
            },
        );
    }
    if roomids.is_empty() {
        error!("No valid rooms. Cannot enable encryption anywhere. Giving up.");
        return Err(Error::EnableEncryptionFailed);
    }
    // without sync() client will not know that it is in joined rooms list and it will fail, we must sync!
    // client.sync_once(SyncSettings::new()).await?; we should have sync-ed before.
    for (i, id) in roomids.iter().enumerate() {
        debug!("In position {} we have room id {:?}.", i, id,);
        match client.get_joined_room(&id) {
            Some(room) => match room.enable_encryption().await {
                Ok(_) => {
                    debug!("enable_encryption succeeded for room {:?}.", id);
                }
                Err(ref e) => {
                    err_count += 1;
                    error!(
                        "enable_encryption failed for room {:?} with reported error {:?}.",
                        id, e
                    );
                }
            },
            None => {
                err_count += 1;
                error!(concat!(
                    "get_joined_room failed for room {:?}, ",
                    "Are you member of this room? If you are member of this room try syncing first."), id);
            }
        }
    }
    if err_count != 0 {
        Err(Error::EnableEncryptionFailed)
    } else {
        Ok(())
    }
}

/// Pre-processing for Delete device(s).
/// This will adjust the lists for special shortcuts such as 'me' and '*'.
/// Get password and user if needed.
/// There is no output to stdout except debug and logging information.
/// If successful nothing will be output.
pub(crate) async fn delete_devices_pre(client: &Client, ap: &mut Args) -> Result<(), Error> {
    debug!("Pre-processing for Deleting device(s)");
    get_password(ap);
    if let Some(user) = ap.user.get(0) {
        if let Some(password) = &ap.password {
            let mut hasstar = false;
            for i in &mut ap.delete_device {
                if i.to_lowercase() == "me" {
                    *i = ap.creds.as_ref().unwrap().device_id.to_string();
                }
                if i == "*" {
                    hasstar = true;
                }
            }
            if hasstar {
                ap.delete_device.retain(|x| x != "*");
                let response = client.devices().await?;
                for device in response.devices {
                    ap.delete_device.push(device.device_id.to_string());
                }
            }
            debug!(
                "Preparing to delete these devices for user {:?} with password {:?}: {:?}",
                user, password, ap.delete_device
            );
            delete_devices(client, &ap.delete_device, user, password, ap.output).await
        } else {
            Err(Error::MissingPassword)
        }
    } else {
        Err(Error::MissingUser)
    }
}

/// Delete device(s).
/// There is no output to stdout except debug and logging information.
/// If successful nothing will be output.
pub(crate) async fn delete_devices(
    client: &Client,
    device_ids: &[String], // list of device ids
    user: &str,
    password: &str,
    _output: Output, // how to format output, currently no output
) -> Result<(), Error> {
    debug!("Deleting device(s)");
    let mut err_count = 0u32;
    // convert Vec of strings into a slice of array of OwnedDeviceIds
    let mut deviceids: Vec<OwnedDeviceId> = Vec::new();
    for device_id in device_ids {
        let deviceid: OwnedDeviceId = device_id.as_str().into();
        deviceids.push(deviceid);
    }
    debug!(
        "About to delete these devices of user {:?} with password {:?}: {:?}",
        user, password, deviceids
    );
    if let Err(e) = client.delete_devices(&deviceids, None).await {
        if let Some(info) = e.uiaa_response() {
            let mut password = uiaa::Password::new(
                // full user id (@john:some.matrix.org), or just local part (john)
                uiaa::UserIdentifier::UserIdOrLocalpart(user),
                password,
            );
            password.session = info.session.as_deref();

            match client
                .delete_devices(&deviceids, Some(uiaa::AuthData::Password(password)))
                .await
            {
                Ok(_) => {
                    info!("Deleted devices {:?} successfully.", deviceids);
                }
                Err(ref e) => {
                    error!("Error: delete_devices() returned error {:?}.", e);
                    err_count += 1;
                }
            }
        }
    }
    if err_count != 0 {
        Err(Error::DeleteDeviceFailed)
    } else {
        Ok(())
    }
}

/// Send one or more text message
/// supporting various formats and types.
pub(crate) async fn message(
    client: &Client,
    msgs: &[String],
    roomnames: &[String],
    code: bool,
    markdown: bool,
    notice: bool,
    emote: bool,
) -> Result<(), Error> {
    debug!(
        "In message(): roomnames are {:?}, msgs are {:?}",
        roomnames, msgs
    );
    if roomnames.is_empty() {
        return Err(Error::InvalidRoom);
    }
    let mut fmsgs: Vec<MessageType> = Vec::new(); // formatted msgs
    let mut fmt_msg: String;
    for msg in msgs.iter() {
        let (nmsg, md) = if code {
            fmt_msg = String::from("```");
            // fmt_msg.push_str("name-of-language");  // Todo
            fmt_msg.push('\n');
            fmt_msg.push_str(msg);
            if !fmt_msg.ends_with('\n') {
                fmt_msg.push('\n');
            }
            fmt_msg.push_str("```");
            (&fmt_msg, true)
        } else {
            (msg, markdown)
        };

        let fmsg = if notice {
            MessageType::Notice(if md {
                NoticeMessageEventContent::markdown(nmsg)
            } else {
                NoticeMessageEventContent::plain(nmsg)
            })
        } else if emote {
            MessageType::Emote(if md {
                EmoteMessageEventContent::markdown(nmsg)
            } else {
                EmoteMessageEventContent::plain(nmsg)
            })
        } else {
            MessageType::Text(if md {
                TextMessageEventContent::markdown(nmsg)
            } else {
                TextMessageEventContent::plain(nmsg)
            })
        };
        fmsgs.push(fmsg);
    }
    if fmsgs.is_empty() {
        return Ok(()); // nothing to do
    }
    let mut err_count = 0u32;
    for roomname in roomnames.iter() {
        let proom = RoomId::parse(roomname).unwrap();
        debug!("In message(): parsed room name is {:?}", proom);
        let room = client.get_joined_room(&proom).ok_or(Error::InvalidRoom)?;
        for fmsg in fmsgs.iter() {
            match room
                .send(RoomMessageEventContent::new(fmsg.clone()), None)
                .await
            {
                Ok(response) => debug!("message send successful {:?}", response),
                Err(ref e) => {
                    error!("message send returned error {:?}", e);
                    err_count += 1;
                }
            }
        }
    }
    if err_count == 0 {
        Ok(())
    } else {
        Err(Error::SendFailed)
    }
}

/// Send one or more files,
/// allows various Mime formats.
// If a file is piped in from stdin, then use the 'stdin_filename' as label for the piped data.
// Implicitely this label also determines the MIME type of the piped data.
pub(crate) async fn file(
    client: &Client,
    filenames: &[PathBuf],
    roomnames: &[String],
    label: Option<&str>, // used as filename for attachment
    mime: Option<Mime>,
    stdin_filename: &PathBuf, // if a file is piped in on stdin
) -> Result<(), Error> {
    debug!(
        "In file(): roomnames are {:?}, files are {:?}",
        roomnames, filenames
    );
    if roomnames.is_empty() {
        return Err(Error::InvalidRoom);
    }
    if filenames.is_empty() {
        return Ok(()); // nothing to do
    }
    let mut err_count = 0u32;
    let mut pb: PathBuf;
    for roomname in roomnames.iter() {
        let proom = RoomId::parse(roomname).unwrap();
        debug!("In file(): parsed room name is {:?}", proom);
        let room = client.get_joined_room(&proom).ok_or(Error::InvalidRoom)?;
        for mut filename in filenames.iter() {
            let data = if filename.to_str().unwrap() == "-" {
                // read from stdin
                let mut buffer = Vec::new();
                if atty::is(Stream::Stdin) {
                    print!("Waiting for data to be piped into stdin. Enter data now: ");
                    std::io::stdout()
                        .flush()
                        .expect("error: could not flush stdout");
                }
                // read the whole file
                io::stdin().read_to_end(&mut buffer)?;
                // change filename from "-" to "file" so that label shows up as "file"
                filename = stdin_filename;
                buffer
            } else {
                if filename.to_str().unwrap() == r"\-" {
                    pb = PathBuf::from(r"-").clone();
                    filename = &pb;
                }
                fs::read(filename).unwrap_or_else(|e| {
                    error!("file not found: {:?} {:?}", filename, e);
                    err_count += 1;
                    Vec::new()
                })
            };
            if data.is_empty() {
                error!("No data to send. Data is empty.");
                err_count += 1;
            } else {
                match room
                    .send_attachment(
                        label
                            .map(Cow::from)
                            .or_else(|| filename.file_name().as_ref().map(|o| o.to_string_lossy()))
                            .ok_or(Error::InvalidFile)?
                            .as_ref(),
                        mime.as_ref().unwrap_or(
                            &mime_guess::from_path(filename)
                                .first_or(mime::APPLICATION_OCTET_STREAM),
                        ),
                        &data,
                        AttachmentConfig::new(),
                    )
                    .await
                {
                    Ok(response) => debug!("file send successful {:?}", response),
                    Err(ref e) => {
                        error!("file send returned error {:?}", e);
                        err_count += 1;
                    }
                }
            }
        }
    }
    if err_count == 0 {
        Ok(())
    } else {
        Err(Error::SendFailed)
    }
}

/// Upload one or more files to the server.
/// Allows various Mime formats.
pub(crate) async fn media_upload(
    client: &Client,
    filenames: &[PathBuf],
    mime_strings: &[String],
    output: Output,
) -> Result<(), Error> {
    debug!(
        "In media_upload(): filename are {:?}, mimes are {:?}",
        filenames, mime_strings,
    );
    let num = filenames.len();
    let mut i = 0usize;
    let mut mime_strings2 = mime_strings.to_owned();
    mime_strings2.resize(num, "".to_string());

    let mut err_count = 0u32;
    let mut filename;
    let mut mime_str;
    let mut mime;
    while i < num {
        filename = filenames[i].clone();
        mime_str = mime_strings2[i].clone();
        debug!(
            "In position {} we have filename {:?}, mime {:?}.",
            i, filename, mime_str
        );
        if mime_str.trim().is_empty() {
            mime = mime_guess::from_path(&filename).first_or(mime::APPLICATION_OCTET_STREAM);
        } else {
            mime = match mime_str.parse() {
                Ok(m) => m,
                Err(ref e) => {
                    error!("Provided Mime {:?} is not valid; the upload of file {:?} will be skipped; returned error {:?}", mime_str, filename, e);
                    err_count += 1;
                    i += 1;
                    continue;
                }
            }
        }

        let data = if filename.to_str().unwrap() == "-" {
            // read from stdin
            let mut buffer = Vec::new();
            if atty::is(Stream::Stdin) {
                eprint!("Waiting for data to be piped into stdin. Enter data now: ");
                std::io::stdout()
                    .flush()
                    .expect("error: could not flush stderr");
            }
            // read the whole file
            io::stdin().read_to_end(&mut buffer)?;
            buffer
        } else {
            if filename.to_str().unwrap() == r"\-" {
                filename = PathBuf::from(r"-");
            }
            fs::read(&filename).unwrap_or_else(|e| {
                error!("File {:?} was not found; the upload of file {:?} will be skipped; returned error {:?}", filename, filename, e);
                err_count += 1;
                Vec::new()
            })
        };
        if data.is_empty() {
            error!(
                "No data to send. Data is empty. The upload of file {:?} will be skipped.",
                filename
            );
            err_count += 1;
        } else {
            match client.media().upload(&mime, &data).await {
                Ok(response) => {
                    debug!("upload successful {:?}", response);
                    print_json(
                        &json::object!(file_name: filename.to_str(),
                        upload_mxc_uri: response.content_uri.as_str(),
                        mime: mime.to_string()),
                        output,
                    );
                }
                Err(ref e) => {
                    error!(
                        "The upload of file {:?} failed. Upload returned error {:?}",
                        filename, e
                    );
                    err_count += 1;
                }
            }
        }
        i += 1;
    }
    if err_count == 0 {
        Ok(())
    } else {
        Err(Error::MediaUploadFailed)
    }
}

/// Download one or more files from the server based on XMC URI.
/// Allows various Mime formats.
pub(crate) async fn media_download(
    client: &Client,
    mxc_uris: &[OwnedMxcUri],
    filenames: &[PathBuf],
    output: Output, // how to format output, currently no output
) -> Result<(), Error> {
    debug!(
        "In media_download(): mxc_uris are {:?}, filenames are {:?}",
        mxc_uris, filenames,
    );
    let num = mxc_uris.len();
    let mut i = 0usize;
    let mut filenames2 = filenames.to_owned();
    filenames2.resize(num, PathBuf::new());

    let mut err_count = 0u32;
    let mut mxc_uri;
    let mut filename;
    while i < num {
        mxc_uri = mxc_uris[i].clone();
        filename = filenames2[i].clone();
        debug!(
            "In position {} we have mxc_uri {:?}, filename {:?}.",
            i, mxc_uri, filename
        );
        if filename.as_os_str().is_empty() {
            filename = PathBuf::from("mxc-".to_owned() + mxc_uri.media_id().unwrap_or(""));
        } else if filename.to_string_lossy().contains("__mxc_id__") {
            filename = PathBuf::from(filename.to_string_lossy().replacen(
                "__mxc_id__",
                mxc_uri.media_id().unwrap_or(""),
                10,
            ));
        }
        let request = MediaRequest {
            source: MediaSource::Plain(mxc_uri.clone()),
            format: MediaFormat::File,
        };
        match client.media().get_media_content(&request, false).await {
            Ok(response) => {
                debug!("dowload successful: {:?} bytes received", response.len());
                if filename.to_str().unwrap() == "-" {
                    match std::io::stdout().write_all(&response) {
                        Ok(_) => {
                            debug!("Downloaded media was successfully written to stdout.");
                            print_json(
                                &json::object!(download_mxc_uri: mxc_uri.as_str(), file_name: "-", size: response.len()),
                                output,
                            );
                        }
                        Err(ref e) => {
                            error!("The downloaded media data could not be written to stdout. write() returned error {:?}", e);
                            err_count += 1;
                            continue;
                        }
                    }
                } else {
                    if filename.to_str().unwrap() == r"\-" {
                        filename = PathBuf::from(r"-");
                    }
                    match File::create(&filename).map(|mut o| o.write_all(&response)) {
                        Ok(Ok(())) => {
                            debug!(
                                "Downloaded media was successfully written to file {:?}.",
                                filename
                            );
                            if response.is_empty() {
                                warn!("The download of MXC URI had 0 bytes of data. It is empty.");
                            };
                            print_json(
                                &json::object!(download_mxc_uri: mxc_uri.as_str(), file_name: filename.to_str(), size: response.len()),
                                output,
                            );
                        }
                        Ok(Err(ref e)) => {
                            error!("Writing downloaded media to file {:?} failed. Error returned is {:?}",filename,e);
                            err_count += 1;
                        }
                        Err(ref e) => {
                            error!("Could not create file {:?} for storing downloaded media. Returned error {:?}.",filename,e);
                            err_count += 1;
                        }
                    }
                };
            }
            Err(ref e) => {
                error!(
                    "The download of MXC URI {:?} failed. Download returned error {:?}",
                    mxc_uri, e
                );
                err_count += 1;
            }
        }
        i += 1;
    }
    if err_count == 0 {
        Ok(())
    } else {
        Err(Error::MediaDownloadFailed)
    }
}

// Todo: remove media content thumbnails

/// Delete one or more files from the server based on XMC URI.
/// Does not delete Thumbnails.
pub(crate) async fn media_delete(
    client: &Client,
    mxc_uris: &[OwnedMxcUri],
    _output: Output, // how to format output
) -> Result<(), Error> {
    debug!("In media_delete(): mxc_uris are {:?}", mxc_uris,);
    let mut err_count = 0u32;
    for mxc in mxc_uris {
        match mxc.validate() {
            Ok(()) => {
                debug!("mxc {:?} is valid.", mxc);
                match client.media().remove_media_content_for_uri(mxc).await {
                    Ok(()) => {
                        debug!("Successfully deleted MXC URI {:?}.", mxc);
                    }
                    Err(ref e) => {
                        error!(
                            "Deleting the MXC URI {:?} failed. Error returned is {:?}.",
                            mxc, e
                        );
                        err_count += 1;
                    }
                }
            }
            Err(ref e) => {
                error!("Invalid MXC URI {:?}. Error returned is {:?}.", mxc, e);
                err_count += 1;
            }
        }
    }
    if err_count == 0 {
        Ok(())
    } else {
        Err(Error::MediaDeleteFailed)
    }
}

/// Convert one or more XMC URIs to HTTP URLs. This is for legacy reasons
/// and compatibility with Python version of matrix-commander.
/// This works without a server and without being logged in.
/// Converts a string like "mxc://matrix.server.org/SomeStrangeUriKey"
/// to a string like "https://matrix.server.org/_matrix/media/r0/download/matrix.server.org/SomeStrangeUriKey".
pub(crate) async fn media_mxc_to_http(
    mxc_uris: &[OwnedMxcUri],
    default_homeserver: &Url,
    output: Output, // how to format output
) -> Result<(), Error> {
    debug!("In media_mxc_to_http(): mxc_uris are {:?}", mxc_uris,);
    let mut err_count = 0u32;
    let mut http;
    for mxc in mxc_uris {
        match mxc.validate() {
            Ok(()) => {
                let p = default_homeserver.as_str()
                    [0..default_homeserver.as_str().find('/').unwrap() - 1]
                    .to_string(); // http or https
                let (server_name, media_id) = mxc.parts().unwrap();
                debug!(
                    "MXC URI {:?} is valid. Protocol is {:?}, Server is {:?}, media id is {:?}.",
                    mxc, p, server_name, media_id
                );
                http = p
                    + "://"
                    + server_name.as_str()
                    + "/_matrix/media/r0/download/"
                    + server_name.as_str()
                    + "/"
                    + media_id;
                debug!("http of mxc {:?} is {:?}", mxc, http);
                print_json(
                    &json::object!(mxc_uri: mxc.as_str(), http: http, media_id: media_id),
                    output,
                );
            }
            Err(ref e) => {
                error!("Invalid MXC URI {:?}. Error returned is {:?}.", mxc, e);
                err_count += 1;
            }
        }
    }
    if err_count == 0 {
        Ok(())
    } else {
        Err(Error::MediaMxcToHttpFailed)
    }
}
