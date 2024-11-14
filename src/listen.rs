//
// https://www.github.com/8go/matrix-commander-rs
// listen.rs
//

//! Module that bundles code together that uses the `matrix-sdk` API.
//! Primarily the matrix_sdk::Client API
//! (see <https://docs.rs/matrix-sdk/latest/matrix_sdk/struct.Client.html>).
//! This module implements the matrix-sdk-based portions of the primitives
//! 'listen', i.e. receiving and listening.

//use std::borrow::Cow;
// use std::env;
//use std::fs;
// use std::fs::File;
// use std::io::{self, Write};
// use std::ops::Deref;
// use std::path::Path;
//use serde::{Deserialize, Serialize};
//use serde_json::Result;
// use std::path::PathBuf;
use tracing::{debug, error, info, warn};
// use thiserror::Error;
// use directories::ProjectDirs;
// use serde::{Deserialize, Serialize};

use matrix_sdk::{
    config::SyncSettings,
    event_handler::Ctx,
    // SessionMeta,
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
            AudioMessageEventContent,
            // EmoteMessageEventContent,
            FileMessageEventContent,
            ImageMessageEventContent,
            MessageType,
            // NoticeMessageEventContent,
            // OriginalRoomMessageEvent, OriginalSyncRoomMessageEvent,
            // RedactedRoomMessageEventContent, RoomMessageEvent,
            // OriginalSyncRoomEncryptedEvent,
            RedactedSyncRoomMessageEvent,
            RoomMessageEventContent,
            SyncRoomMessageEvent,
            TextMessageEventContent,
            VideoMessageEventContent,
        },
        events::room::redaction::{
            OriginalSyncRoomRedactionEvent, RedactedSyncRoomRedactionEvent, SyncRoomRedactionEvent,
        },
        events::{
            AnyMessageLikeEvent,
            AnyTimelineEvent,
            MessageLikeEvent,
            OriginalSyncMessageLikeEvent,
            // OriginalMessageLikeEvent, // MessageLikeEventContent,
            SyncMessageLikeEvent,
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

/// Declare the items used from main.rs
use crate::{Error, Output};

/// Lower-level utility function to handle originalsyncmessagelikeevent
fn handle_originalsyncmessagelikeevent(
    ev: &OriginalSyncMessageLikeEvent<RoomMessageEventContent>,
    room_id: &OwnedRoomId,
    context: &Ctx<EvHandlerContext>,
) {
    // --output json is handled above this level,
    // if Json is output this event processing is never needed and never reached
    debug!(
        "New message: {:?} from sender {:?}, room {:?}, event_id {:?}",
        ev.content,
        ev.sender,
        room_id, // ev does not contain room!
        ev.event_id,
    );
    if context.whoami != ev.sender || context.listen_self {
        // The compiler knows that it is RoomMessageEventContent, because it comes from room::messages()
        // print_type_of(&orginialmessagelikeevent.content); // ruma_common::events::room::message::RoomMessageEventContent
        match ev.content.msgtype.to_owned() {
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
                    body, room_id, ev.sender, ev.event_id, formatted,
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
                    body, room_id, ev.sender, ev.event_id, filename, source, info,
                );
            }
            MessageType::Image(imagemessageeventcontent) => {
                // debug!("Msg of type File");
                let ImageMessageEventContent {
                    body, source, info, ..
                } = imagemessageeventcontent;
                println!(
                    "Message: type Image: body {:?}, room {:?}, sender {:?}, event id {:?}, source {:?}, info {:?}",
                    body, room_id, ev.sender, ev.event_id, source, info,
                );
            }
            MessageType::Audio(audiomessageeventcontent) => {
                // debug!("Msg of type File");
                let AudioMessageEventContent {
                    body, source, info, ..
                } = audiomessageeventcontent;
                println!(
                    "Message: type Image: body {:?}, room {:?}, sender {:?}, event id {:?}, source {:?}, info {:?}",
                    body, room_id, ev.sender, ev.event_id, source, info,
                );
            }
            MessageType::Video(videomessageeventcontent) => {
                // debug!("Msg of type File");
                let VideoMessageEventContent {
                    body, source, info, ..
                } = videomessageeventcontent;
                println!(
                    "Message: type Image: body {:?}, room {:?}, sender {:?}, event id {:?}, source {:?}, info {:?}",
                    body, room_id, ev.sender, ev.event_id, source, info,
                );
            }
            _ => {
                debug!("Not handling this event: {:?}", ev);
                warn!(
                    "Not handling this message type. Not implemented yet. {:?}",
                    ev
                );
            }
        }
    } else {
        debug!("Skipping message from itself because --listen-self is not set.");
    }
}

/// Utility function to handle RedactedSyncRoomMessageEvent events.
// None of the args can be borrowed because this function is passed into a spawned process.
async fn handle_redactedsyncroommessageevent(
    ev: RedactedSyncRoomMessageEvent,
    room: Room,
    _client: Client,
    context: Ctx<EvHandlerContext>,
) {
    debug!(
        "Received a message for RedactedSyncRoomMessageEvent. {:?}",
        ev
    );
    if context.whoami == ev.sender && !context.listen_self {
        debug!("Skipping message from itself because --listen-self is not set.");
        return;
    }
    if !context.output.is_text() {
        // Serialize it to a JSON string.
        let j = match serde_json::to_string(&ev.content) {
            Ok(jsonstr) => {
                // this event does not contain the room_id, other events do.
                // People are missing the room_id in output.
                // Nasty hack: inserting the room_id into the JSON string.
                let mut s = jsonstr;
                s.insert_str(s.len() - 1, ",\"event_id\":\"\"");
                s.insert_str(s.len() - 2, ev.event_id.as_str());
                s.insert_str(s.len() - 1, ",\"sender\":\"\"");
                s.insert_str(s.len() - 2, ev.sender.as_str());
                s.insert_str(s.len() - 1, ",\"origin_server_ts\":\"\"");
                s.insert_str(s.len() - 2, &ev.origin_server_ts.0.to_string());
                s.insert_str(s.len() - 1, ",\"room_id\":\"\"");
                s.insert_str(s.len() - 2, room.room_id().as_str());
                s
            }
            Err(e) => e.to_string(),
        };
        println!("{}", j);
        return;
    }
    debug!(
        "Received a message for RedactedSyncRoomMessageEvent. Not implemented yet for text format, try --output json. {:?}",
        ev
    );
}

fn handle_originalsyncroomredactionevent(ev: OriginalSyncRoomRedactionEvent, room: Room) {
    debug!(
        "Received a message for OriginalSyncRoomRedactionEvent. {:?}",
        ev
    );
    // Serialize it to a JSON string.
    let j = match serde_json::to_string(&ev.content) {
        Ok(jsonstr) => {
            // this event does not contain the room_id, other events do.
            // People are missing the room_id in output.
            // Nasty hack: inserting the room_id into the JSON string.
            let mut s = jsonstr;
            s.insert_str(s.len() - 1, ",\"event_id\":\"\"");
            s.insert_str(s.len() - 2, ev.event_id.as_str());
            s.insert_str(s.len() - 1, ",\"sender\":\"\"");
            s.insert_str(s.len() - 2, ev.sender.as_str());
            s.insert_str(s.len() - 1, ",\"origin_server_ts\":\"\"");
            s.insert_str(s.len() - 2, &ev.origin_server_ts.0.to_string());
            s.insert_str(s.len() - 1, ",\"room_id\":\"\"");
            s.insert_str(s.len() - 2, room.room_id().as_str());
            s
        }
        Err(e) => e.to_string(),
    };
    println!("{}", j);
}

fn handle_redactedsyncroomredactionevent(ev: RedactedSyncRoomRedactionEvent, room: Room) {
    debug!(
        "Received a message for RedactedSyncRoomRedactionEvent. {:?}",
        ev
    );
    // Serialize it to a JSON string.
    let j = match serde_json::to_string(&ev.content) {
        Ok(jsonstr) => {
            // this event does not contain the room_id, other events do.
            // People are missing the room_id in output.
            // Nasty hack: inserting the room_id into the JSON string.
            let mut s = jsonstr;
            s.insert_str(s.len() - 1, ",\"event_id\":\"\"");
            s.insert_str(s.len() - 2, ev.event_id.as_str());
            s.insert_str(s.len() - 1, ",\"sender\":\"\"");
            s.insert_str(s.len() - 2, ev.sender.as_str());
            s.insert_str(s.len() - 1, ",\"origin_server_ts\":\"\"");
            s.insert_str(s.len() - 2, &ev.origin_server_ts.0.to_string());
            s.insert_str(s.len() - 1, ",\"room_id\":\"\"");
            s.insert_str(s.len() - 2, room.room_id().as_str());
            s
        }
        Err(e) => e.to_string(),
    };
    println!("{}", j);
}

/// Utility function to handle SyncRoomRedactionEvent events.
// None of the args can be borrowed because this function is passed into a spawned process.
async fn handle_syncroomredactedevent(
    ev: SyncRoomRedactionEvent,
    room: Room,
    _client: Client,
    context: Ctx<EvHandlerContext>,
) {
    debug!("Received a message for SyncRoomRedactionEvent. {:?}", ev);
    if context.whoami == ev.sender() && !context.listen_self {
        debug!("Skipping message from itself because --listen-self is not set.");
        return;
    }
    if !context.output.is_text() {
        // Serialize it to a JSON string.
        match ev {
            SyncRoomRedactionEvent::Original(evi) => {
                handle_originalsyncroomredactionevent(evi, room)
            }
            SyncRoomRedactionEvent::Redacted(evi) => {
                handle_redactedsyncroomredactionevent(evi, room)
            }
        }
        return;
    }
    debug!(
        "Received a message for SyncRoomRedactionEvent. Not implemented yet for text format, try --output json. {:?}",
        ev
    );
}

/// Utility function to handle SyncRoomEncryptedEvent events.
// None of the args can be borrowed because this function is passed into a spawned process.
async fn handle_syncroomencryptedevent(
    ev: SyncRoomEncryptedEvent,
    room: Room,
    _client: Client,
    context: Ctx<EvHandlerContext>,
) {
    debug!("Received a SyncRoomEncryptedEvent message {:?}", ev);
    if context.whoami == ev.sender() && !context.listen_self {
        debug!("Skipping message from itself because --listen-self is not set.");
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
            // let jroom = join_room();
            // let _res = jroom.decrypt_event(&ev).await?;
            // Todo: attempt to decrypt msg
        }
        _ => {
            debug!(
                "Received a message for RedactedSyncMessageLikeEvent. Not implemented yet. {:?}",
                ev
            );
        }
    }
    warn!("Decryption attempt not implemented yet.");
}

/// Utility function to handle OriginalSyncRoomEncryptedEvent events.
// None of the args can be borrowed because this function is passed into a spawned process.
async fn handle_originalsyncroomencryptedevent(
    ev: OriginalSyncRoomEncryptedEvent,
    room: Room,
    _client: Client,
    context: Ctx<EvHandlerContext>,
) {
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
}

/// Utility function to handle SyncRoomMessageEvent events.
// None of the args can be borrowed because this function is passed into a spawned process.
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
    match ev {
        SyncMessageLikeEvent::Original(orginialmessagelikeevent) => {
            if !context.output.is_text() {
                // Serialize it to a JSON string.
                let j = match serde_json::to_string(&orginialmessagelikeevent.content) {
                    Ok(jsonstr) => {
                        // this event does not contain the room_id, other events do.
                        // People are missing the room_id in output.
                        // Nasty hack: inserting the room_id into the JSON string.
                        let mut s = jsonstr;
                        s.insert_str(s.len() - 1, ",\"event_id\":\"\"");
                        s.insert_str(s.len() - 2, orginialmessagelikeevent.event_id.as_str());
                        s.insert_str(s.len() - 1, ",\"sender\":\"\"");
                        s.insert_str(s.len() - 2, orginialmessagelikeevent.sender.as_str());
                        s.insert_str(s.len() - 1, ",\"origin_server_ts\":\"\"");
                        s.insert_str(s.len() - 2, &orginialmessagelikeevent.origin_server_ts.0.to_string());
                        s.insert_str(s.len() - 1, ",\"room_id\":\"\"");
                        s.insert_str(s.len() - 2, room.room_id().as_str());
                        s
                    }
                    Err(e) => e.to_string(),
                };
                println!("{}", j);
                return;
            }
            handle_originalsyncmessagelikeevent(
                &orginialmessagelikeevent,
                &RoomId::parse(room.room_id()).unwrap(),
                &context,
            );
        }
        _ => {
            debug!(
                "Received a message for RedactedSyncMessageLikeEvent. Not implemented yet. {:?}",
                ev
            );
        }
    };
}

/// Data structure needed to pass additional arguments into the event handler
#[derive(Clone, Debug)]
struct EvHandlerContext {
    whoami: OwnedUserId,
    listen_self: bool,
    output: Output,
}

/// Listen to all rooms once. Then continue.
pub(crate) async fn listen_once(
    client: &Client,
    listen_self: bool, // listen to my own messages?
    whoami: OwnedUserId,
    output: Output,
) -> Result<(), Error> {
    info!(
        "mclient::listen_once(): listen_self {}, room {}",
        listen_self, "all"
    );

    let context = EvHandlerContext {
        whoami,
        listen_self,
        output,
    };

    client.add_event_handler_context(context.clone());

    // Todo: print events nicely and filter by --listen-self
    client.add_event_handler(|ev: SyncRoomMessageEvent, room: Room,
        client: Client, context: Ctx<EvHandlerContext>| async move {
        tokio::spawn(handle_syncroommessageevent(ev, room, client, context));
    });

    client.add_event_handler(
        |ev: RedactedSyncRoomMessageEvent,
         room: Room,
         client: Client,
         context: Ctx<EvHandlerContext>| async move {
            tokio::spawn(handle_redactedsyncroommessageevent(
                ev, room, client, context,
            ));
        },
    );

    client.add_event_handler(
        |ev: SyncRoomRedactionEvent,
         room: Room,
         client: Client,
         context: Ctx<EvHandlerContext>| async move {
            tokio::spawn(handle_syncroomredactedevent(ev, room, client, context));
        },
    );

    client.add_event_handler(
        |ev: OriginalSyncRoomEncryptedEvent,
         room: Room,
         client: Client,
         context: Ctx<EvHandlerContext>| async move {
            tokio::spawn(handle_originalsyncroomencryptedevent(
                ev, room, client, context,
            ));
        },
    );

    client.add_event_handler(
        |ev: SyncRoomEncryptedEvent,
         room: Room,
         client: Client,
         context: Ctx<EvHandlerContext>| async move {
            tokio::spawn(handle_syncroomencryptedevent(ev, room, client, context));
        },
    );

    // go into event loop to sync and to execute verify protocol
    info!("Ready and getting messages from server...");

    // get the current sync state from server before syncing
    // This gets all rooms but ignores msgs from itself.
    let settings = SyncSettings::default();

    client.sync_once(settings).await?;
    Ok(())
}

/// Listen to all rooms forever. Stay in the event loop.
pub(crate) async fn listen_forever(
    client: &Client,
    listen_self: bool, // listen to my own messages?
    whoami: OwnedUserId,
    output: Output,
) -> Result<(), Error> {
    info!(
        "mclient::listen_forever(): listen_self {}, room {}",
        listen_self, "all"
    );

    let context = EvHandlerContext {
        whoami,
        listen_self,
        output,
    };

    client.add_event_handler_context(context.clone());

    // Todo: print events nicely and filter by --listen-self
    client.add_event_handler(
        |ev: SyncRoomMessageEvent, room: Room, client: Client, context: Ctx<EvHandlerContext>| async move {
        tokio::spawn(handle_syncroommessageevent(ev, room, client, context));
    });

    client.add_event_handler(
        |ev: SyncRoomEncryptedEvent, room: Room, client: Client, context: Ctx<EvHandlerContext>| async move {
        tokio::spawn(handle_syncroomencryptedevent(ev, room, client, context));
    });

    client.add_event_handler(
        |ev: OriginalSyncRoomEncryptedEvent,
         room: Room,
         client: Client,
         context: Ctx<EvHandlerContext>| async move {
            tokio::spawn(handle_originalsyncroomencryptedevent(
                ev, room, client, context,
            ));
        },
    );

    client.add_event_handler(
        |ev: RedactedSyncRoomMessageEvent,
         room: Room,
         client: Client,
         context: Ctx<EvHandlerContext>| async move {
            tokio::spawn(handle_redactedsyncroommessageevent(
                ev, room, client, context,
            ));
        },
    );

    client.add_event_handler(|ev: SyncRoomRedactionEvent,
            room: Room, client: Client, context: Ctx<EvHandlerContext>| async move {
            tokio::spawn(handle_syncroomredactedevent(ev, room, client, context));
        });

    // go into event loop to sync and to execute verify protocol
    info!("Ready and waiting for messages ...");
    info!("Once done listening, kill the process manually with Control-C.");

    // get the current sync state from server before syncing
    let settings = SyncSettings::default();

    match client.sync(settings).await {
        Ok(()) => Ok(()),
        Err(e) => {
            // this does not catch Control-C
            error!("Event loop reported: {:?}", e);
            Ok(())
        }
    }
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
    client: &Client,
    roomnames: &Vec<String>, // roomId
    number: u64,             // number of messages to print, N
    listen_self: bool,       // listen to my own messages?
    whoami: OwnedUserId,
    output: Output,
) -> Result<(), Error> {
    info!(
        "mclient::listen_tail(): listen_self {}, roomnames {:?}",
        listen_self, roomnames
    );
    if roomnames.is_empty() {
        return Err(Error::MissingRoom);
    }

    // We are *not* using the event manager, no sync()!

    info!("Ready and getting messages from server ...");

    // convert Vec of strings into a slice of array of OwnedRoomIds
    let mut roomids: Vec<OwnedRoomId> = Vec::new();
    for roomname in roomnames {
        roomids.push(match RoomId::parse(roomname.clone()) {
            Ok(id) => id,
            Err(ref e) => {
                error!(
                    "Error: invalid room id {:?}. Error reported is {:?}.",
                    roomname, e
                );
                continue;
            }
        });
    }
    let ownedroomidvecoption: Option<Vec<OwnedRoomId>> = Some(roomids.clone());
    // // old code, when there was only 1 roomname
    // let roomclone = roomnames[0].clone();
    // let ownedroomid: OwnedRoomId = RoomId::parse(&roomclone).unwrap();
    // let ownedroomidvec = ownedroomid
    // let ownedroomidvecoption: Option<Vec<OwnedRoomId>> = Some(ownedroomid);
    let mut filter = FilterDefinition::default();
    let mut roomfilter = RoomFilter::empty();
    roomfilter.rooms = ownedroomidvecoption;
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

    let context = EvHandlerContext {
        whoami: whoami.clone(),
        listen_self,
        output,
    };
    let ctx = Ctx(context);

    let mut err_count = 0u32;
    for roomid in roomids.iter() {
        let mut options = MessagesOptions::backward(); // .from("t47429-4392820_219380_26003_2265");
        options.limit = UInt::new(number).unwrap();
        let jroom = client.get_room(roomid.clone().as_ref()).unwrap();
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
            if !output.is_text() {
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
                                    let room_id = orginialmessagelikeevent.room_id.clone();
                                    let orginialsyncmessagelikeevent =
                                        OriginalSyncMessageLikeEvent::from(
                                            orginialmessagelikeevent,
                                        );
                                    handle_originalsyncmessagelikeevent(
                                        &orginialsyncmessagelikeevent,
                                        &room_id,
                                        &ctx,
                                    );
                                }
                                _ => {
                                    warn!("RoomMessage type is not handled. Not implemented yet.");
                                    err_count += 1;
                                }
                            }
                        }
                        AnyMessageLikeEvent::RoomEncrypted(messagelikeevent) => {
                            warn!(
                                "Event of type RoomEncrypted received: {:?}",
                                messagelikeevent
                            );
                            // messagelikeevent is something like
                            // RoomEncrypted: Original(OriginalMessageLikeEvent { content: RoomEncryptedEventContent { scheme: MegolmV1AesSha2(MegolmV1AesSha2Content { ciphertext: "xxx", sender_key: "yyy", device_id: "DDD", session_id: "sss" }), relates_to: Some(_Custom) }, event_id: "$eee", sender: "@sss:some.homeserver.org", origin_server_ts: MilliSecondsSinceUnixEpoch(123), room_id: "!roomid:some.homeserver.org",
                            //      unsigned: MessageLikeUnsigned { age: Some(123), transaction_id: None, relations: None } })
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
                                            orginialmessagelikeevent.content, orginialmessagelikeevent.room_id, orginialmessagelikeevent.sender, orginialmessagelikeevent.event_id,
                                        );
                                        // has orginialmessagelikeevent.content.relates_to.unwrap()
                                    } else {
                                        debug!("Skipping message from itself because --listen-self is not set.");
                                    }
                                }
                                _ => {
                                    warn!("RoomMessage type is not handled. Not implemented yet.");
                                    err_count += 1;
                                }
                            }
                        }
                        AnyMessageLikeEvent::RoomRedaction(messagelikeevent) => {
                            warn!("Event of type RoomRedaction received. Not implemented yet. value: {:?}", messagelikeevent);
                            err_count += 1;
                        }
                        // and many more
                        _ => {
                            warn!("MessageLike type is not handle. Not implemented yet.");
                            err_count += 1;
                        }
                    }
                }
                _ => debug!("State event, not interested in that."),
            }
        }
    }
    if err_count != 0 {
        Err(Error::NotImplementedYet)
    } else {
        Ok(())
    }
}

/// Listen to some specified rooms once, then go on.
/// Listens to the room(s) provided as argument, prints any pending relevant messages,
/// and then continues by returning.
pub(crate) async fn listen_all(
    client: &Client,
    roomnames: &Vec<String>, // roomId
    listen_self: bool,       // listen to my own messages?
    whoami: OwnedUserId,
    output: Output,
) -> Result<(), Error> {
    if roomnames.is_empty() {
        return Err(Error::MissingRoom);
    }
    info!(
        "mclient::listen_all(): listen_self {}, roomnames {:?}",
        listen_self, roomnames
    );

    let context = EvHandlerContext {
        whoami,
        listen_self,
        output,
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
        |ev: RedactedSyncRoomMessageEvent,
         room: Room,
         client: Client,
         context: Ctx<EvHandlerContext>| async move {
            tokio::spawn(handle_redactedsyncroommessageevent(
                ev, room, client, context,
            ));
        },
    );

    client.add_event_handler(|ev: SyncRoomRedactionEvent,
        room: Room, client: Client, context: Ctx<EvHandlerContext>| async move {
        tokio::spawn(handle_syncroomredactedevent(ev, room, client, context));
    });

    // go into event loop to sync and to execute verify protocol
    info!("Ready and waiting for messages ...");

    // search for filter: https://docs.rs/matrix-sdk/0.6.2/matrix_sdk/struct.Client.html#method.builder
    // https://docs.rs/ruma/latest/ruma/api/client/filter/struct.FilterDefinition.html
    // https://docs.rs/ruma/latest/ruma/api/client/filter/struct.RoomFilter.html  ==> timeline, rooms
    // https://docs.rs/ruma/latest/ruma/api/client/filter/struct.RoomEventFilter.html  ==> limit : max number of events to return, types :: event types to include; rooms: rooms to include

    let mut roomids: Vec<OwnedRoomId> = Vec::new();
    for roomname in roomnames {
        roomids.push(RoomId::parse(roomname.clone()).unwrap());
    }
    let ownedroomidvecoption: Option<Vec<OwnedRoomId>> = Some(roomids);
    // Filter by rooms. This works.
    let mut filter = FilterDefinition::default();
    let mut roomfilter = RoomFilter::empty();
    roomfilter.rooms = ownedroomidvecoption;
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

    let mut err_count = 0u32;
    let filterclone = filter.clone();
    let sync_settings = SyncSettings::default().filter(Filter::FilterDefinition(filterclone));

    match client.sync_once(sync_settings).await {
        Ok(response) => debug!("listen_all successful {:?}", response),
        Err(ref e) => {
            err_count += 1;
            error!("listen_all returned error {:?}", e);
        }
    }
    if err_count != 0 {
        Err(Error::ListenFailed)
    } else {
        Ok(())
    }
}
