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
        // UserId,
        OwnedRoomId,
        // OwnedRoomOrAliasId, OwnedServerName,
        // device_id, room_id, session_id, user_id, OwnedDeviceId, OwnedUserId,
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
use crate::{credentials_exist, get_timeout, Credentials, GlobalState};
use crate::{Error, Listen, Output, Sync};

// import verification code
#[path = "emoji_verify.rs"]
mod emoji_verify;

/// Constructor for matrix-sdk async Client, based on restore_login().
pub(crate) async fn restore_login(gs: &mut GlobalState) -> Result<Client, Error> {
    if gs.credentials_file_path.is_file() {
        let credentials = Credentials::load(&gs.credentials_file_path)?;
        debug!("restore_login: credentials are {:?}", &credentials);
        let clihomeserver = gs.ap.homeserver.clone();
        let homeserver = clihomeserver.unwrap_or_else(|| credentials.homeserver.clone());
        info!(
            "restoring device with device_id = {:?} on homeserver {:?}.",
            &credentials.device_id, &homeserver
        );
        let session: matrix_sdk::Session = credentials.clone().into();
        gs.credentials = Some(credentials);
        let client = create_client(&homeserver, gs).await?;
        client.restore_login(session).await?;
        if gs.ap.listen == Listen::Never {
            sync_once(&client, get_timeout(gs), gs.ap.sync).await?;
        } else {
            info!("Skipping sync due to --listen");
        }
        Ok(client)
    } else {
        Err(Error::NotLoggedIn)
    }
}

/// Constructor for matrix-sdk async Client, based on login_username().
pub(crate) async fn login<'a>(
    gs: &'a mut GlobalState,
    homeserver: &Url,
    username: &str,
    password: &str,
    device: &str,
    room_default: &str,
) -> Result<Client, Error> {
    let client = create_client(homeserver, gs).await?;
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
    info!("credentials file = {:?}", gs.credentials_file_path);

    Credentials::new(
        homeserver.clone(),
        session.user_id.clone(),
        session.access_token.clone(),
        session.device_id.clone(),
        room_default.to_string(),
        session.refresh_token.clone(),
    )
    .save(&gs.credentials_file_path)?;
    info!(
        "new credentials file created = {:?}",
        gs.credentials_file_path
    );
    if gs.ap.listen == Listen::Never {
        sync_once(&client, get_timeout(gs), gs.ap.sync).await?;
    } else {
        info!("Skipping sync due to --listen");
    }
    Ok(client)
}

/// Prepares a client that can then be used for actual login.
/// Configures the matrix-sdk async Client.
async fn create_client(homeserver: &Url, gs: &GlobalState) -> Result<Client, Error> {
    // The location to save files to
    let sledhome = &gs.sledstore_dir_path;
    info!("Using sled store {:?}", &sledhome);
    // let builder = if let Some(proxy) = cli.proxy { builder.proxy(proxy) } else { builder };
    let builder = Client::builder()
        .homeserver_url(homeserver)
        .store_config(StoreConfig::new())
        .request_config(
            RequestConfig::new()
                .timeout(Duration::from_secs(get_timeout(gs)))
                .retry_timeout(Duration::from_secs(get_timeout(gs))),
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
pub(crate) async fn verify(client: &Result<Client, Error>) -> Result<(), Error> {
    if let Ok(client) = client {
        // is logged in
        info!("Client logged in: {}", client.logged_in());
        info!("Client access token used: {:?}", client.access_token());
        emoji_verify::sync(client).await?; // wait in sync for other party to initiate emoji verify
        Ok(())
    } else {
        Err(Error::NotLoggedIn)
    }
}

/// Logs out, destroying the device and removing credentials file
pub(crate) async fn logout(client: &Result<Client, Error>, gs: &GlobalState) -> Result<(), Error> {
    debug!("Logout on client");
    if let Ok(client) = client {
        // is logged in
        logout_server(client, gs).await?;
    }
    if credentials_exist(gs) {
        match fs::remove_file(&gs.credentials_file_path) {
            Ok(()) => info!(
                "Credentials file successfully remove {:?}",
                &gs.credentials_file_path
            ),
            Err(e) => error!(
                "Error: credentials file not removed. {:?} {:?}",
                &gs.credentials_file_path, e
            ),
        }
    } else {
        warn!(
            "Credentials file does not exist {:?}",
            &gs.credentials_file_path
        )
    }

    match fs::remove_dir_all(&gs.sledstore_dir_path) {
        Ok(()) => info!(
            "Sled directory successfully remove {:?}",
            &gs.sledstore_dir_path
        ),
        Err(e) => error!(
            "Error: Sled directory not removed. {:?} {:?}",
            &gs.sledstore_dir_path, e
        ),
    }
    Ok(())
}

/// Only logs out from server, no local changes.
pub(crate) async fn logout_server(client: &Client, gs: &GlobalState) -> Result<(), Error> {
    if gs.ap.logout.is_me() {
        match client.logout().await {
            Ok(n) => info!("Logout sent to server {:?}", n),
            Err(e) => error!(
                "Error: Server logout failed but we remove local device id anyway. {:?}",
                e
            ),
        }
    }
    // TODO: `all`
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
pub(crate) async fn devices(
    clientres: &Result<Client, Error>,
    output: Output,
) -> Result<(), Error> {
    debug!("Devices on server");
    if let Ok(client) = clientres {
        // is logged in
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
    } else {
        Err(Error::NotLoggedIn)
    }
}

/// Get room info for a list of rooms.
/// Includes items such as room id, room display name, room alias, and room topic.
pub(crate) async fn get_room_info(
    clientres: &Result<Client, Error>,
    rooms: &[String],
    output: Output,
) -> Result<(), Error> {
    debug!("Getting room info");
    if let Ok(client) = clientres {
        // is logged in
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
    } else {
        Err(Error::NotLoggedIn)
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
    clientres: &Result<Client, Error>,
    rooms: Option<matrix_sdk::RoomType>, // None is the default and prints all 3 types of rooms
    output: Output,
) -> Result<(), Error> {
    debug!("Rooms (local)");
    if let Ok(client) = clientres {
        // is logged in
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
    } else {
        Err(Error::NotLoggedIn)
    }
}

/// Print list of all rooms (invited, joined, left) of the current user.
pub(crate) async fn rooms(clientres: &Result<Client, Error>, output: Output) -> Result<(), Error> {
    debug!("Rooms (local)");
    print_rooms(clientres, None, output)
}

/// Print list of all invited rooms (not joined, not left) of the current user.
pub(crate) async fn invited_rooms(
    clientres: &Result<Client, Error>,
    output: Output,
) -> Result<(), Error> {
    debug!("Invited_rooms (local)");
    print_rooms(clientres, Some(matrix_sdk::RoomType::Invited), output)
}

/// Print list of all joined rooms (not invited, not left) of the current user.
pub(crate) async fn joined_rooms(
    clientres: &Result<Client, Error>,
    output: Output,
) -> Result<(), Error> {
    debug!("Joined_rooms (local)");
    print_rooms(clientres, Some(matrix_sdk::RoomType::Joined), output)
}

/// Print list of all left rooms (not invited, not joined) of the current user.
pub(crate) async fn left_rooms(
    clientres: &Result<Client, Error>,
    output: Output,
) -> Result<(), Error> {
    debug!("Left_rooms (local)");
    print_rooms(clientres, Some(matrix_sdk::RoomType::Left), output)
}

/// Create rooms, one for each alias name in the list.
/// Alias name can be empty, i.e. ''.
/// If and when available set the room name from the name list.
/// If and when available set the topic name from the topic list.
/// As output it lists/prints the newly generated room ids and and the corresponding room aliases.
pub(crate) async fn room_create(
    clientres: &Result<Client, Error>,
    room_aliases: &[String], // list of simple alias names like 'SomeAlias', not full aliases
    room_names: &[String],   // list of room names, optional
    room_topics: &[String],  // list of room topics, optional
    output: Output,          // how to format output
) -> Result<(), Error> {
    debug!("Creating room(s)");
    let mut err_count = 0u32;
    if let Ok(client) = clientres {
        // is logged in
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
    } else {
        Err(Error::NotLoggedIn)
    }
}

/// Leave room(s), leave all the rooms whose ids are given in the list.
/// There is no output to stdout except debug and logging information.
/// If successful nothing will be output.
pub(crate) async fn room_leave(
    clientres: &Result<Client, Error>,
    room_ids: &[String], // list of room ids
    _output: Output,     // how to format output, currently no output
) -> Result<(), Error> {
    debug!("Leaving room(s)");
    let mut err_count = 0u32;
    if let Ok(client) = clientres {
        // is logged in
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
    } else {
        Err(Error::NotLoggedIn)
    }
}

/// Forget room(s), forget all the rooms whose ids are given in the list.
/// Before you can forget a room you must leave it first.
/// There is no output to stdout except debug and logging information.
/// If successful nothing will be output.
pub(crate) async fn room_forget(
    clientres: &Result<Client, Error>,
    room_ids: &[String], // list of room ids
    _output: Output,     // how to format output, currently no output
) -> Result<(), Error> {
    debug!("Forgetting room(s)");
    let mut err_count = 0u32;
    if let Ok(client) = clientres {
        // is logged in
        debug!("All rooms of this user: {:?}.", client.rooms());
        // get latest room states
        // client.sync_once(SyncSettings::new()).await?;   // Todo: sync necessary?
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
    } else {
        Err(Error::NotLoggedIn)
    }
}

/// Send one or more text message
/// supporting various formats and types.
pub(crate) async fn message(
    client: &Result<Client, Error>,
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
    if client.is_err() {
        return Err(Error::InvalidClientConnection);
    }
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
        let room = client
            .as_ref()
            .unwrap()
            .get_joined_room(&proom)
            .ok_or(Error::InvalidRoom)?;
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
    client: &Result<Client, Error>,
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
    if client.is_err() {
        return Err(Error::InvalidClientConnection);
    }
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
        let room = client
            .as_ref()
            .unwrap()
            .get_joined_room(&proom)
            .ok_or(Error::InvalidRoom)?;
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
