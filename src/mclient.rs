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
use std::borrow::Cow;
use std::io::{self, Read, Write};
// use std::env;
use std::fs;
// use std::fs::File;
// use std::io::{self, Write};
// use std::ops::Deref;
// use std::path::Path;
use std::path::PathBuf;
use tracing::{debug, error, info, warn};
// use thiserror::Error;
// use directories::ProjectDirs;
// use serde::{Deserialize, Serialize};
//use serde_json::Result;
use mime::Mime;
use url::Url;

use matrix_sdk::{
    attachment::AttachmentConfig,
    config::{RequestConfig, StoreConfig, SyncSettings},
    instant::Duration,
    // Session,
    room,
    // room::Room,
    // ruma::
    ruma::{
        api::client::room::create_room::v3::Request as CreateRoomRequest,
        api::client::uiaa,
        // OwnedRoomOrAliasId, OwnedServerName,
        // device_id,
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
        // DeviceId,
        // room_id, session_id, user_id,
        OwnedDeviceId,
        OwnedRoomAliasId,
        // UserId,
        OwnedRoomId,
        RoomAliasId,
        // UInt,
        // OwnedRoomAliasId,
        // OwnedRoomId,
        // OwnedUserId,
        // serde::Raw,
        // events::OriginalMessageLikeEvent,
        RoomId,
    },
    Client,
};

// from main.rs
use crate::{credentials_exist, get_password, Args, Credentials, Error, Listen, Output, Sync};

// import verification code
#[path = "emoji_verify.rs"]
mod emoji_verify;

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
                            el.push_str(&res.room_id.to_string());
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

/// Create rooms, one for each alias name in the list.
/// Alias name can be empty, i.e. ''.
/// If and when available set the room name from the name list.
/// If and when available set the topic name from the topic list.
/// As output it lists/prints the newly generated room ids and and the corresponding room aliases.
pub(crate) async fn room_create(
    client: &Client,
    room_aliases: &[String], // list of simple alias names like 'SomeAlias', not full aliases
    room_names: &[String],   // list of room names, optional
    room_topics: &[String],  // list of room topics, optional
    output: Output,          // how to format output
) -> Result<(), Error> {
    debug!("Creating room(s)");
    let mut err_count = 0u32;
    for (i, a) in room_aliases.iter().enumerate() {
        // a...alias
        debug!(
            "In position {} we have alias name {}, room name {:?}, room topic {:?}.",
            i,
            a,
            room_names.get(i),
            room_topics.get(i)
        );
        let aopt = if a.is_empty() { None } else { Some(a.as_str()) };
        let nopt = match room_names.get(i) {
            Some(inner) => {
                if inner.is_empty() {
                    None
                } else {
                    Some(inner.as_str())
                }
            }
            None => None,
        };
        let topt = match room_topics.get(i) {
            Some(inner) => {
                if inner.is_empty() {
                    None
                } else {
                    Some(inner.as_str())
                }
            }
            None => None,
        };
        let mut request = CreateRoomRequest::new();
        request.name = nopt;
        request.room_alias_name = aopt;
        request.topic = topt;
        match client.create_room(request).await {
            Ok(response) => {
                debug!("create_room succeeded, result is {:?}.", response);
                if output.is_text() {
                    println!(
                        "{}    {}    {}    {}",
                        response.room_id,
                        aopt.unwrap_or("None"),
                        nopt.unwrap_or("None"),
                        topt.unwrap_or("None")
                    );
                } else {
                    // all json formats
                    // trait Serialize not implemented for Result
                    let mut jstr: String = "{".to_owned();
                    jstr.push_str(&format!("\"room_id\": \"{}\"", response.room_id));
                    if let Some(alias) = aopt {
                        jstr.push_str(&format!(", \"alias\": \"{}\"", alias))
                    }
                    if let Some(name) = nopt {
                        jstr.push_str(&format!(", \"name\": \"{}\"", name))
                    }
                    if let Some(topic) = topt {
                        jstr.push_str(&format!(", \"topic\": \"{}\"", topic))
                    }
                    jstr.push('}');
                    println!("{}", jstr);
                }
            }
            Err(ref e) => {
                err_count += 1;
                error!("Error: create_room failed, reported error {:?}.", e);
            }
        }
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
    debug!("All rooms of this user: {:?}.", client.rooms());
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
