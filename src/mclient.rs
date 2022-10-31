//
// https://www.github.com/8go/matrix-commander-rs
// mclient.rs
//

//! Module that bundles everything together that uses the `matrix-sdk` API.
//! Primarily the matrix_sdk::Client API
//! (see <https://docs.rs/matrix-sdk/latest/matrix_sdk/struct.Client.html>).
//! This module implements the matrix-sdk-based portions of the primitives like
//! logging in, logging out, verifying, sending messages, sending files, etc.

use std::borrow::Cow;
// use std::env;
use std::fs;
// use std::fs::File;
// use std::io::{self, Write};
// use std::ops::Deref;
// use std::path::Path;
//use serde::{Deserialize, Serialize};
//use serde_json::Result;
use std::path::PathBuf;
use tracing::{debug, error, info, warn};
// use thiserror::Error;
// use directories::ProjectDirs;
// use serde::{Deserialize, Serialize};
use mime::Mime;
use url::Url;

use matrix_sdk::{
    attachment::AttachmentConfig,
    config::{RequestConfig, StoreConfig, SyncSettings},
    event_handler::Ctx,
    instant::Duration,
    // Session,
    room::MessagesOptions,
    // room,
    room::Room,
    // ruma::
    ruma::{
        api::client::{
            filter::{FilterDefinition, /* LazyLoadOptions, */ RoomEventFilter, RoomFilter},
            sync::sync_events::v3::Filter,
            // sync::sync_events,
        },
        events::room::encrypted::{
            OriginalSyncRoomEncryptedEvent,
            /* RoomEncryptedEventContent, */ SyncRoomEncryptedEvent,
        },
        events::room::message::{
            EmoteMessageEventContent,
            FileMessageEventContent,
            MessageType,
            NoticeMessageEventContent,
            // OriginalRoomMessageEvent, OriginalSyncRoomMessageEvent, RedactedRoomMessageEventContent, RoomMessageEvent,
            // OriginalSyncRoomEncryptedEvent,
            RedactedSyncRoomMessageEvent,
            RoomMessageEventContent,
            SyncRoomMessageEvent,
            TextMessageEventContent,
        },
        events::room::redaction::SyncRoomRedactionEvent,
        events::{
            AnyMessageLikeEvent,
            AnyTimelineEvent,
            MessageLikeEvent,
            SyncMessageLikeEvent, // OriginalMessageLikeEvent, // MessageLikeEventContent,
        },
        // OwnedRoomAliasId,
        OwnedRoomId,
        OwnedUserId,
        // serde::Raw,
        // events::OriginalMessageLikeEvent,
        RoomId,
        // UserId,
        // OwnedRoomId, OwnedRoomOrAliasId, OwnedServerName,
        // device_id, room_id, session_id, user_id, OwnedDeviceId, OwnedUserId,
        UInt,
    },
    Client,
};

use crate::{credentials_exist, get_timeout, Credentials, GlobalState};
use crate::{Error, Listen, Output, Sync}; // from main.rs

#[path = "emoji_verify.rs"]
mod emoji_verify; // import verification code

/// Constructor for matrix-sdk async Client, based on restore_login().
pub(crate) async fn restore_login(gs: &mut GlobalState) -> Result<Client, Error> {
    if gs.credentials_file_path.is_file() {
        let credentials = Credentials::load(&gs.credentials_file_path)?;
        let credentialsc1 = credentials.clone();
        let credentialsc2 = credentials.clone();
        gs.credentials = Some(credentials);
        let client = create_client(credentialsc1.homeserver, gs).await?;
        info!(
            "restoring device with device_id = {:?}",
            credentialsc1.device_id
        );
        client.restore_login(credentialsc2.into()).await?;
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
    let client = create_client(homeserver.clone(), gs).await?;
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
async fn create_client(homeserver: Url, gs: &GlobalState) -> Result<Client, Error> {
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
        .sled_store(&sledhome, None)
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
        emoji_verify::sync(&client).await?; // wait in sync for other party to initiate emoji verify
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
        logout_server(&client).await?;
    }
    if credentials_exist(&gs) {
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
pub(crate) async fn logout_server(client: &Client) -> Result<(), Error> {
    match client.logout().await {
        Ok(n) => info!("Logout sent to server {:?}", n),
        Err(e) => error!(
            "Error: Server logout failed but we remove local device id anyway. {:?}",
            e
        ),
    }
    Ok(())
}

// Todo: when is this sync() really necessary? send seems to work without, listen do not need it, devices does not need it but forces it to consume msgs, ...
/// Utility function to synchronize once.
pub(crate) async fn sync_once(client: &Client, timeout: u64, stype: Sync) -> Result<(), Error> {
    debug!("value of sync in sync_once() is {:?}", stype);
    match stype {
        Sync::Off => {
            info!("syncing is turned off. No syncing.");
            Ok(())
        }
        Sync::Full => {
            info!("syncing once, timeout set to {} seconds ...", timeout);
            client
                .sync_once(SyncSettings::new().timeout(Duration::new(timeout, 0)))
                .await?; // sec
            info!("sync completed");
            Ok(())
        }
    }
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

/// Get list of devices for the current user.
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
                    "{{\"device_id\": {}, \"display_name\": {}}}",
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
pub(crate) async fn get_room_info(
    clientres: &Result<Client, Error>,
    rooms: Vec<String>,
    output: Output,
) -> Result<(), Error> {
    debug!("Getting room info");
    if let Ok(client) = clientres {
        // is logged in
        for (i, roomstr) in rooms.iter().enumerate() {
            debug!("Room number {} with room id {}", i, roomstr);
            let room_id = match RoomId::parse(&roomstr) {
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
                    room.name().unwrap_or("".to_string()), // alternatively: room.display_name().await.ok().unwrap(),
                    match room.canonical_alias() {
                        Some(inner) => inner.to_string(),
                        _ => "".to_string(),
                    },
                    room.topic().unwrap_or("".to_string()),
                    // user_id of room creator,
                    // encrypted boolean
                ),
                Output::JsonSpec => (),
                _ => println!(
                    "{{\"room_id\": {:?}, \"display_name\": {:?}, \"alias\": {:?}, \"topic\": {:?}}}",
                    room_id,
                    room.name().unwrap_or("".to_string()), // alternatively: room.display_name().await.ok().unwrap(),
                    match room.canonical_alias() {
                        Some(inner) => inner.to_string(),
                        _ => "".to_string(),
                    },
                    room.topic().unwrap_or("".to_string()),
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

/// Sent text message is various formats and types.
pub(crate) async fn message(
    client: &Result<Client, Error>,
    msg: String,
    room: String,
    code: bool,
    markdown: bool,
    notice: bool,
    emote: bool,
) -> Result<(), Error> {
    if client.is_err() {
        return Err(Error::InvalidClientConnection);
    }
    debug!("In message(): room is {}, msg is {}", room, msg);
    let (nmsg, md) = if code {
        let mut fmt_msg = String::from("```");
        // fmt_msg.push_str("name-of-language");  // Todo
        fmt_msg.push('\n');
        fmt_msg.push_str(&msg);
        if !fmt_msg.ends_with('\n') {
            fmt_msg.push('\n');
        }
        fmt_msg.push_str("```");
        (fmt_msg, true)
    } else {
        (msg, markdown)
    };

    let content = if notice {
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
    let proom = RoomId::parse(room).unwrap();
    debug!("In message(): parsed room is {:?}", proom);
    client
        .as_ref()
        .unwrap()
        .get_joined_room(&proom)
        .ok_or(Error::InvalidRoom)?
        .send(RoomMessageEventContent::new(content), None)
        .await?;
    Ok(())
}

/// Send a file of various Mime formats.
pub(crate) async fn file(
    client: &Result<Client, Error>,
    filename: PathBuf,
    room: String,          // RoomId
    label: Option<String>, // used as filename for attachment
    mime: Option<Mime>,
) -> Result<(), Error> {
    if client.is_err() {
        return Err(Error::InvalidClientConnection);
    }
    let data = fs::read(&filename)?;
    let proom = RoomId::parse(room).unwrap();
    client
        .as_ref()
        .unwrap()
        .get_joined_room(&proom)
        .ok_or(Error::InvalidRoom)?
        .send_attachment(
            label
                .as_ref()
                .map(Cow::from)
                .or_else(|| filename.file_name().as_ref().map(|o| o.to_string_lossy()))
                .ok_or(Error::InvalidFile)?
                .as_ref(),
            mime.as_ref().unwrap_or(
                &mime_guess::from_path(&filename).first_or(mime::APPLICATION_OCTET_STREAM),
            ),
            &data,
            AttachmentConfig::new(),
        )
        .await?;
    Ok(())
}

/// Utility function to handle SyncRoomMessageEvent event.
async fn handle_syncroommessageevent(
    ev: SyncRoomMessageEvent,
    room: Room,
    _client: Client,
    context: Ctx<EvHandlerContext>,
) {
    debug!("Received a message for event SyncRoomMessageEvent {:?}", ev);
    if context.whoami == ev.sender() && !context.listen_self {
        debug!("Skipping message from itself because --listen-self is not set.");
        return;
    }
    if context.output != Output::Text {
        // Serialize it to a JSON string.
        let j = match serde_json::to_string(&ev) {
            Ok(jsonstr) => jsonstr,
            Err(e) => e.to_string(),
        };
        println!("{}", j);
        return;
    }
    match ev {
        SyncMessageLikeEvent::Original(orginialmessagelikeevent) => {
            debug!(
                "New message: {:?} from sender {:?}, room {:?}, event_id {:?}",
                orginialmessagelikeevent.content,
                orginialmessagelikeevent.sender,
                room.room_id(), // "<unknown>", // ev does not contain room!
                orginialmessagelikeevent.event_id,
            );
            if context.whoami != orginialmessagelikeevent.sender || context.listen_self {
                // The compiler knows that it is RoomMessageEventContent, because it comes from room::messages()
                // print_type_of(&orginialmessagelikeevent.content); // ruma_common::events::room::message::RoomMessageEventContent
                match orginialmessagelikeevent.content.msgtype {
                    MessageType::Text(textmessageeventcontent) => {
                        // debug!("Msg of type Text");
                        let TextMessageEventContent {
                            body,
                            formatted,
                            // message,
                            ..
                        } = textmessageeventcontent;
                        println!(
                            "Message: type Text: body {:?}, room {:?}, sender {:?}, event id {:?}, formatted {:?}, ",
                            body, room.room_id(), orginialmessagelikeevent.sender, orginialmessagelikeevent.event_id, formatted,
                        );
                    }
                    MessageType::File(filemessageeventcontent) => {
                        // debug!("Msg of type File");
                        let FileMessageEventContent {
                            body,
                            filename,
                            source,
                            info,
                            // message,
                            // file,
                            ..
                        } = filemessageeventcontent;
                        println!(
                            "Message: type File: body {:?}, room {:?}, sender {:?}, event id {:?}, filename {:?}, source {:?}, info {:?}",
                            body, "<unknown>", orginialmessagelikeevent.sender, orginialmessagelikeevent.event_id, filename, source, info,
                        );
                    }
                    _ => warn!("Not handling this message type. Not implemented yet."),
                }
            } else {
                debug!("Skipping message from itself because --listen-self is not set.");
            }
        }
        _ => {
            debug!(
                "Received a message for RedactedSyncMessageLikeEvent. Not implemented yet. {:?}",
                ev
            );
        }
    };
}

#[derive(Clone, Debug)]
struct EvHandlerContext {
    whoami: OwnedUserId,
    listen_self: bool,
    output: Output,
}

/// Listen to all rooms once. Then continue.
pub(crate) async fn listen_once(
    clientres: &Result<Client, Error>,
    listen_self: bool, // listen to my own messages?
    whoami: OwnedUserId,
    output: Output,
) -> Result<(), Error> {
    let client = match clientres {
        Err(e) => {
            error!("error: {:?}", e);
            return Err(Error::InvalidClientConnection);
        }
        Ok(client) => client,
    };
    info!(
        "mclient::listen_once(): listen_self {}, room {}",
        listen_self, "all"
    );

    let context = EvHandlerContext {
        whoami: whoami,
        listen_self: listen_self,
        output: output,
    };

    client.add_event_handler_context(context.clone());

    // Todo: print events nicely and filter by --listen-self
    client.add_event_handler(|ev: SyncRoomMessageEvent, room: Room, client: Client, context: Ctx<EvHandlerContext>| async move {
        tokio::spawn(handle_syncroommessageevent(ev, room, client, context));
    });

    client.add_event_handler(
        |ev: RedactedSyncRoomMessageEvent,
         _room: Room,
         _client: Client,
         context: Ctx<EvHandlerContext>| async move {
            debug!(
                "Received a message for RedactedSyncRoomMessageEvent. {:?}",
                ev
            );
            if context.whoami == ev.sender && !context.listen_self {
                debug!("Skipping message from itself because --listen-self is not set.");
                return;
            }
            if context.output != Output::Text {
                // Serialize it to a JSON string.
                let j = match serde_json::to_string(&ev) {
                    Ok(jsonstr) => jsonstr,
                    Err(e) => e.to_string(),
                };
                println!("{}", j);
                return;
            }
            debug!(
                "Received a message for RedactedSyncRoomMessageEvent. Not implemented yet for text format, try --output json. {:?}",
                ev
            );
        },
    );

    client.add_event_handler(|ev: SyncRoomRedactionEvent, _room: Room,
         _client: Client,
         context: Ctx<EvHandlerContext>| async move {
            debug!(
                "Received a message for SyncRoomRedactionEvent. {:?}",
                ev
            );
            if context.whoami == ev.sender() && !context.listen_self {
                debug!("Skipping message from itself because --listen-self is not set.");
                return;
            }
            if context.output != Output::Text {
                // Serialize it to a JSON string.
                let j = match serde_json::to_string(&ev) {
                    Ok(jsonstr) => jsonstr,
                    Err(e) => e.to_string(),
                };
                println!("{}", j);
                return;
            }
            debug!(
                "Received a message for SyncRoomRedactionEvent. Not implemented yet for text format, try --output json. {:?}",
                ev
            );
    });

    client.add_event_handler(
        |ev: OriginalSyncRoomEncryptedEvent,
         room: Room,
         _client: Client,
         context: Ctx<EvHandlerContext>| async move {
            debug!("Received a OriginalSyncRoomEncryptedEvent message {:?}", ev);
            if context.whoami == ev.sender && !context.listen_self {
                debug!("Skipping message from itself because --listen-self is not set.");
                return;
            }
            debug!(
                "New message: {:?} from sender {:?}, room {:?}, event_id {:?}",
                ev.content,
                ev.sender,
                room.room_id(), // "<unknown>", // ev does not contain room!
                ev.event_id,
            );
            // let jroom = join_room();
            // let _res = jroom.decrypt_event(&ev).await?;
            // Todo: attempt to decrypt msg
            warn!("Decryption attempt not implemented yet.");
        },
    );

    client.add_event_handler(|ev: SyncRoomRedactionEvent,
        _room: Room,
        _client: Client,
        context: Ctx<EvHandlerContext>| async move {
            debug!(
                "Received a message for SyncRoomRedactionEvent. {:?}",
                ev,
            );
            if context.whoami == ev.sender() && !context.listen_self {
                debug!("Skipping message from itself because --listen-self is not set.");
                return;
            }
            if context.output != Output::Text {
                // Serialize it to a JSON string.
                let j = match serde_json::to_string(&ev) {
                    Ok(jsonstr) => jsonstr,
                    Err(e) => e.to_string(),
                };
                println!("{}", j);
                return;
            }
            debug!(
                "Received a message for SyncRoomRedactionEvent. Not implemented yet for text format, try --output json. {:?}",
                ev
            );
    });

    // go into event loop to sync and to execute verify protocol
    info!("Ready and getting messages from server...");

    // get the current sync state from server before syncing
    // This gets all rooms but ignores msgs from itself.
    let settings = SyncSettings::default().token(client.sync_token().await.unwrap());

    client.sync_once(settings).await?;
    Ok(())
}

/// Listen to all rooms forever. Stay in the event loop.
pub(crate) async fn listen_forever(
    clientres: &Result<Client, Error>,
    listen_self: bool, // listen to my own messages?
    whoami: OwnedUserId,
    output: Output,
) -> Result<(), Error> {
    let client = match clientres {
        Err(e) => {
            error!("error: {:?}", e);
            return Err(Error::InvalidClientConnection);
        }
        Ok(client) => client,
    };
    info!(
        "mclient::listen_forever(): listen_self {}, room {}",
        listen_self, "all"
    );

    let context = EvHandlerContext {
        whoami: whoami,
        listen_self: listen_self,
        output: output,
    };

    client.add_event_handler_context(context.clone());

    // Todo: print events nicely and filter by --listen-self
    client.add_event_handler(|ev: SyncRoomMessageEvent, room: Room, client: Client, context: Ctx<EvHandlerContext>| async move {
        tokio::spawn(handle_syncroommessageevent(ev, room, client, context));
    });

    client.add_event_handler(
        |ev: RedactedSyncRoomMessageEvent, _client: Client| async move {
            println!(
                "Received a message for RedactedSyncRoomMessageEvent {:?}",
                ev
            );
        },
    );

    client.add_event_handler(|ev: SyncRoomEncryptedEvent, _client: Client| async move {
        println!("Received a message for SyncRoomEncryptedEvent {:?}", ev);
    });

    client.add_event_handler(
        |ev: OriginalSyncRoomEncryptedEvent, _client: Client| async move {
            println!("Received a OriginalSyncRoomEncryptedEvent message {:?}", ev);
        },
    );

    client.add_event_handler(|ev: SyncRoomRedactionEvent, _client: Client| async move {
        println!("Received a message for SyncRoomRedactionEvent {:?}", ev);
    });

    // go into event loop to sync and to execute verify protocol
    info!("Ready and waiting for messages ...");
    info!("Once done listening, kill the process manually with Control-C.");

    // get the current sync state from server before syncing
    let settings = SyncSettings::default().token(client.sync_token().await.unwrap());

    client.sync(settings).await?;
    Ok(())
}

#[allow(dead_code)]
fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>())
}

/// Get last N messages from some specified rooms once, then go on.
/// Listens to the room(s) specified in the argument, prints the last N messasges.
/// The read messages can be already read ones or new unread ones.
/// Then it returns. Less than N messages might be printed if the messages do not exist.
/// Running it twice in a row (while no new messages were sent) should deliver the same output, response.
pub(crate) async fn listen_tail(
    clientres: &Result<Client, Error>,
    room: String,      // RoomId // Todo: should be vector of user specified rooms
    number: u64,       // Number of messages to print, N
    listen_self: bool, // listen to my own messages?
    whoami: OwnedUserId,
    output: Output,
) -> Result<(), Error> {
    let client = match clientres {
        Err(e) => {
            error!("error: {:?}", e);
            return Err(Error::InvalidClientConnection);
        }
        Ok(client) => client,
    };
    let proom = RoomId::parse(room.clone()).unwrap();
    info!(
        "mclient::listen_tail(): listen_self {}, room {:?}",
        listen_self, proom
    );

    // We are *not* using the event manager, no sync()!

    // go into event loop to sync and to execute verify protocol
    info!("Ready and getting messages from server ...");

    // Filter by rooms. This works.
    let mut filter = FilterDefinition::default();
    let mut roomfilter = RoomFilter::empty();
    let roomclone = room.clone();
    let ownedroomid: OwnedRoomId = RoomId::parse(&roomclone).unwrap();
    let ownedroomidarrayslice = &[ownedroomid][0..1]; // from 0 to 1 exl, ie. from 0 to 1-1, ie from 0 to 0
    let ownedroomidarraysliceoption = Some(ownedroomidarrayslice);
    roomfilter.rooms = ownedroomidarraysliceoption;
    filter.room = roomfilter;

    // Filter by limit. This works.
    // This gets the last N not yet read messages. If all messages had been read, it gets 0 messages.
    let mut roomtimeline = RoomEventFilter::empty();
    roomtimeline.limit = UInt::new(number);
    filter.room.timeline = roomtimeline;

    // see: https://docs.rs/matrix-sdk/0.6.2/src/matrix_sdk/room/common.rs.html#167-200
    // there is also something like next_batch, a value indicating a point in the event timeline
    // prev_batch: https://docs.rs/matrix-sdk/0.6.2/src/matrix_sdk/room/common.rs.html#1142-1180
    // https://docs.rs/matrix-sdk/0.6.2/matrix_sdk/struct.BaseRoom.html#method.last_prev_batch
    // https://docs.rs/matrix-sdk/0.6.2/matrix_sdk/room/struct.Common.html#method.messages
    // https://docs.rs/matrix-sdk/0.6.2/matrix_sdk/room/struct.MessagesOptions.html

    let mut options = MessagesOptions::backward(); // .from("t47429-4392820_219380_26003_2265");
    options.limit = UInt::new(number).unwrap();
    let jroom = client.get_joined_room(&proom).unwrap();
    let msgs = jroom.messages(options).await;
    // debug!("\n\nmsgs = {:?} \n\n", msgs);
    let chunk = msgs.unwrap().chunk;
    for index in 0..chunk.len() {
        debug!(
            "processing message {:?} out of {:?}",
            index + 1,
            chunk.len()
        );
        let anytimelineevent = &chunk[chunk.len() - 1 - index]; // reverse ordering, getting older msg first
                                                                // Todo : dump the JSON serialized string via Json API

        let rawevent: AnyTimelineEvent = anytimelineevent.event.deserialize().unwrap();
        // print_type_of(&rawevent); // ruma_common::events::enums::AnyTimelineEvent
        debug!("rawevent = value is {:?}\n", rawevent);
        // rawevent = Ok(MessageLike(RoomMessage(Original(OriginalMessageLikeEvent { content: RoomMessageEventContent {
        // msgtype: Text(TextMessageEventContent { body: "54", formatted: None }), relates_to: Some(_Custom) }, event_id: "$xxx", sender: "@u:some.homeserver.org", origin_server_ts: MilliSecondsSinceUnixEpoch(123), room_id: "!rrr:some.homeserver.org", unsigned: MessageLikeUnsigned { age: Some(123), transaction_id: None, relations: None } }))))
        if output != Output::Text {
            println!("{}", anytimelineevent.event.json());
            continue;
        }
        match rawevent {
            AnyTimelineEvent::MessageLike(anymessagelikeevent) => {
                debug!("value: {:?}", anymessagelikeevent);
                match anymessagelikeevent {
                    AnyMessageLikeEvent::RoomMessage(messagelikeevent) => {
                        debug!("value: {:?}", messagelikeevent);
                        match messagelikeevent {
                            MessageLikeEvent::Original(orginialmessagelikeevent) => {
                                debug!(
                                    "New message: {:?} from sender {:?}, room {:?}, event_id {:?}",
                                    orginialmessagelikeevent.content,
                                    orginialmessagelikeevent.sender,
                                    orginialmessagelikeevent.room_id,
                                    orginialmessagelikeevent.event_id,
                                );
                                if whoami != orginialmessagelikeevent.sender || listen_self {
                                    // The compiler knows that it is RoomMessageEventContent, because it comes from room::messages()
                                    // print_type_of(&orginialmessagelikeevent.content); // ruma_common::events::room::message::RoomMessageEventContent

                                    match orginialmessagelikeevent.content.msgtype {
                                        MessageType::Text(textmessageeventcontent) => {
                                            // debug!("Msg of type Text");
                                            let TextMessageEventContent {
                                                body,
                                                formatted,
                                                // message,
                                                ..
                                            } = textmessageeventcontent;
                                            println!(
                                            "Message: type Text: body {:?}, room {:?}, sender {:?}, event id {:?}, formatted {:?}, ",
                                            body, orginialmessagelikeevent.room_id, orginialmessagelikeevent.sender, orginialmessagelikeevent.event_id, formatted,
                                            );
                                        }
                                        MessageType::File(filemessageeventcontent) => {
                                            // debug!("Msg of type File");
                                            let FileMessageEventContent {
                                                body,
                                                filename,
                                                source,
                                                info,
                                                // message,
                                                // file,
                                                ..
                                            } = filemessageeventcontent;
                                            println!(
                                            "Message: type File: body {:?}, room {:?}, sender {:?}, event id {:?}, filename {:?}, source {:?}, info {:?}",
                                            body, orginialmessagelikeevent.room_id, orginialmessagelikeevent.sender, orginialmessagelikeevent.event_id, filename, source, info,
                                        );
                                        }
                                        _ => warn!(
                                            "Not handling this message type. Not implemented yet."
                                        ),
                                    }
                                } else {
                                    debug!("Skipping message from itself because --listen-self is not set.");
                                }
                            }
                            _ => warn!("RoomMessage type is not handled. Not implemented yet."),
                        }
                    }
                    AnyMessageLikeEvent::RoomEncrypted(messagelikeevent) => {
                        warn!(
                            "Event of type RoomEncrypted received: {:?}",
                            messagelikeevent
                        );
                        // messagelikeevent is something like
                        // RoomEncrypted: Original(OriginalMessageLikeEvent { content: RoomEncryptedEventContent { scheme: MegolmV1AesSha2(MegolmV1AesSha2Content { ciphertext: "xxx", sender_key: "yyy", device_id: "DDD", session_id: "sss" }), relates_to: Some(_Custom) }, event_id: "$eee", sender: "@sss:some.homeserver.org", origin_server_ts: MilliSecondsSinceUnixEpoch(123), room_id: "!roomid:some.homeserver.org", unsigned: MessageLikeUnsigned { age: Some(123), transaction_id: None, relations: None } })
                        // Cannot be decryoted with jroom.decrypt_event(&anytimelineevent.event).await?;
                        // because decrypt_event() only decrypts events from sync() and not from messages()

                        match messagelikeevent {
                            MessageLikeEvent::Original(orginialmessagelikeevent) => {
                                debug!(
                                    "New message: {:?} from sender {:?}, room {:?}, event_id {:?}",
                                    orginialmessagelikeevent.content,
                                    orginialmessagelikeevent.sender,
                                    orginialmessagelikeevent.room_id,
                                    orginialmessagelikeevent.event_id,
                                );
                                if whoami != orginialmessagelikeevent.sender || listen_self {
                                    // The compiler knows that it is RoomMessageEventContent, because it comes from room::messages()
                                    // print_type_of(&orginialmessagelikeevent.content); // ruma_common::events::room::message::RoomEncryptedEventContent
                                    println!(
                                            "Message: type Encrypted: body {:?}, room {:?}, sender {:?}, event_id {:?}, message could not be decrypted",
                                            orginialmessagelikeevent.content, room, orginialmessagelikeevent.sender, orginialmessagelikeevent.event_id,
                                        );
                                    // has orginialmessagelikeevent.content.relates_to.unwrap()
                                } else {
                                    debug!("Skipping message from itself because --listen-self is not set.");
                                }
                            }
                            _ => warn!("RoomMessage type is not handled. Not implemented yet."),
                        }
                    }
                    AnyMessageLikeEvent::RoomRedaction(messagelikeevent) => {
                        warn!("Event of type RoomRedaction received. Not implemented yet. value: {:?}", messagelikeevent)
                    }
                    // and many more
                    _ => warn!("MessageLike type is not handle. Not implemented yet."),
                }
            }
            _ => debug!("State event, not interested in that."),
        }
    }
    Ok(())
}

/// Listen to some specified rooms once, then go on.
/// Listens to the room(s) provided as argument, prints any pending relevant messages,
/// and then continues by returning.
pub(crate) async fn listen_all(
    clientres: &Result<Client, Error>,
    room: String,      // RoomId // Todo: should be vector of user specified rooms
    listen_self: bool, // listen to my own messages?
    whoami: OwnedUserId,
    output: Output,
) -> Result<(), Error> {
    let client = match clientres {
        Err(e) => {
            error!("error: {:?}", e);
            return Err(Error::InvalidClientConnection);
        }
        Ok(client) => client,
    };
    let proom = RoomId::parse(room.clone()).unwrap();
    info!(
        "mclient::listen_all(): listen_self {}, room {:?}",
        listen_self, proom
    );

    let context = EvHandlerContext {
        whoami: whoami,
        listen_self: listen_self,
        output: output,
    };

    client.add_event_handler_context(context.clone());

    // Todo: print events nicely and filter by --listen-self
    client.add_event_handler(|ev: SyncRoomMessageEvent, room: Room, client: Client, context: Ctx<EvHandlerContext>| async move {
        tokio::spawn(handle_syncroommessageevent(ev, room, client, context));
    });

    // this seems idential to SyncRoomMessageEvent and hence a duplicate
    // client.add_event_handler(
    //     |ev: OriginalSyncRoomMessageEvent, _client: Client| async move {
    //         println!(
    //             "Received a message for OriginalSyncRoomMessageEvent {:?}",
    //             ev
    //         );
    //     },
    // );

    client.add_event_handler(
        |ev: RedactedSyncRoomMessageEvent, _client: Client| async move {
            println!(
                "Received a message for RedactedSyncRoomMessageEvent {:?}",
                ev
            );
        },
    );

    client.add_event_handler(|ev: SyncRoomRedactionEvent, _client: Client| async move {
        println!("Received a message for SyncRoomRedactionEvent {:?}", ev);
    });

    // go into event loop to sync and to execute verify protocol
    info!("Ready and waiting for messages ...");

    // search for filter: https://docs.rs/matrix-sdk/0.6.2/matrix_sdk/struct.Client.html#method.builder
    // https://docs.rs/ruma/latest/ruma/api/client/filter/struct.FilterDefinition.html
    // https://docs.rs/ruma/latest/ruma/api/client/filter/struct.RoomFilter.html  ==> timeline, rooms
    // https://docs.rs/ruma/latest/ruma/api/client/filter/struct.RoomEventFilter.html  ==> limit : max number of events to return, types :: event types to include; rooms: rooms to include

    // Filter by rooms. This works.
    let mut filter = FilterDefinition::default();
    let mut roomfilter = RoomFilter::empty();
    let roomclone = room.clone();
    let ownedroomid: OwnedRoomId = RoomId::parse(&roomclone).unwrap();
    let ownedroomidarrayslice = &[ownedroomid][0..1]; // from 0 to 1 exl, ie. from 0 to 1-1, ie from 0 to 0
    let ownedroomidarraysliceoption = Some(ownedroomidarrayslice);
    roomfilter.rooms = ownedroomidarraysliceoption;
    filter.room = roomfilter;

    // // Let's enable member lazy loading. This filter is enabled by default.
    // filter.room.state.lazy_load_options = LazyLoadOptions::Enabled {
    //     include_redundant_members: false,
    // };

    // // Todo: add future option like --user to filter messages by user id
    // // Filter by user; this works but NOT for itself.
    // // It does not listen to its own messages, additing itself as sender does not help.
    // // The msgs sent by itself are not in this event stream and hence cannot be filtered.
    // let mut roomstate = RoomEventFilter::empty();
    // let userid1: OwnedUserId = UserId::parse("@john:some.homeserver.org").unwrap();
    // let userid2: OwnedUserId = UserId::parse("@jane:some.homeserver.org").unwrap();
    // let useridslice = &[userid1, userid2][0..2];
    // roomstate.senders = Some(useridslice);
    // filter.room.timeline = roomstate;

    // // Filter by limit. This works.
    // // This gets the last N not yet read messages. If all messages had been read, it gets 0 messages.
    // let mut roomtimeline = RoomEventFilter::empty();
    // roomtimeline.limit = UInt::new(number);
    // filter.room.timeline = roomtimeline;

    // To be more efficient, more performant, usually one stores the filter on the
    // server under a given name. This way only the name but not the filter needs to
    // be transferred. But we would have an unlimited amount of filters. How to name them
    // uniquely? To avoid the naming problem, we do not create names but send the filter
    // itself.
    // The filter would be created like so:
    // // some unique naming scheme, dumb example prepending the room id with "room-",
    // // some sort of hash would be better.
    // let filter_name = format!("room-{}", room);
    // let filter_id = client
    //     .get_or_upload_filter(&filter_name, filter)
    //     .await
    //     .unwrap();
    // // now we can use the filter_name in the sync() call
    // let sync_settings = SyncSettings::new().filter(Filter::FilterId(&filter_id));

    // let sync_settings = SyncSettings::default()
    //     .token(client.sync_token().await.unwrap())
    //     .filter(Filter::FilterId(&filter_id));

    let filterclone = filter.clone();
    let sync_settings = SyncSettings::default()
        .token(client.sync_token().await.unwrap())
        .filter(Filter::FilterDefinition(filterclone));

    let _response = client.sync_once(sync_settings).await.unwrap();
    Ok(())
}
