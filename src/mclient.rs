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

use mime::Mime;
use std::borrow::Cow;
use std::io::{self, Read, Write};
// use std::env;
use std::fs;
use std::fs::File;
// use std::ops::Deref;
// use std::path::Path;
use std::io::{stdin, IsTerminal};
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
    // encryption::CryptoStoreError,
    // deserialized_responses::RawSyncOrStrippedState,
    authentication::{matrix::MatrixSession, SessionTokens},
    media::{MediaFormat, MediaRequestParameters},
    room,
    room::{Room, RoomMember},
    ruma::{
        time::Duration,
        api::client::room::create_room::v3::Request as CreateRoomRequest,
        api::client::room::create_room::v3::RoomPreset,
        api::client::room::Visibility,
        api::client::profile::{DisplayName, AvatarUrl},
        api::client::uiaa,
        events::room::encryption::RoomEncryptionEventContent,
        // OwnedRoomOrAliasId, OwnedServerName,
        // device_id,
        events::room::member::RoomMemberEventContent,
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
        events::room::name::RoomNameEventContent,
        events::room::power_levels::{RoomPowerLevelsEventContent/*, UserPowerLevel*/},
        events::room::topic::RoomTopicEventContent,
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
    RoomMemberships,
    SessionMeta,
};

// from main.rs
use crate::{
    credentials_exist, get_password, get_store_default_path,
    Args, Credentials, Error, Listen, Output, Sync,
};

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

/// Convert partial room id, partial room alias, room alias to
/// full room id.
/// !irywieryiwre => !irywieryiwre:matrix.server.com
/// john => !irywieryiwre:matrix.server.com
/// #john => !irywieryiwre:matrix.server.com
/// #john:matrix.server.com => !irywieryiwre:matrix.server.com
pub(crate) async fn convert_to_full_room_id(
    client: &Client,
    room: &mut String,
    default_host: &str,
) {
    room.retain(|c| !c.is_whitespace());
    if room.starts_with('@') {
        error!(
            "This room alias or id {:?} starts with an at sign. \
            @ are used for user ids, not room id or room aliases. \
            This will fail later.",
            room
        );
        return;
    }
    if !room.starts_with('#') && !room.starts_with('!') {
        room.insert(0, '#');
    }
    if !room.contains(':') {
        room.push(':');
        room.push_str(default_host);
    }
    // now we either full room id or full room alias id
    if room.starts_with('!') {
        return;
    }
    if room.starts_with("\\!") {
        room.remove(0); // remove escape
        return;
    }
    if room.starts_with("\\#") {
        room.remove(0); // remove escape
        return;
    }

    if room.starts_with('#') {
        match RoomAliasId::parse(room.clone().replace("\\#", "#")) {
            //remove possible escape
            Ok(id) => match client.resolve_room_alias(&id).await {
                Ok(res) => {
                    room.clear();
                    room.push_str(res.room_id.as_ref());
                }
                Err(ref e) => {
                    error!(
                        "Error: invalid alias {:?}. resolve_room_alias() returned error {:?}.",
                        room, e
                    );
                    room.clear();
                }
            },
            Err(ref e) => {
                error!(
                    "Error: invalid alias {:?}. Error reported is {:?}.",
                    room, e
                );
                room.clear();
            }
        }
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
    let num = vecstr.len();
    let mut i = 0;
    while i < num {
        convert_to_full_room_id(client, &mut vecstr[i], default_host).await;
        i += 1;
    }
    vecstr.retain(|x| !x.trim().is_empty());
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
            error!(
                "This does not seem to be a short MXC URI. Contains : or /. \
                Skipping {:?}. This will likely cause a failure later.",
                vecstr[i]
            );
            i += 1;
            continue;
        }
        let mxc = format!("mxc://{default_host}/{s}");
        vecstr[i] = OwnedMxcUri::from(mxc);
        if !vecstr[i].is_valid() {
            error!(
                "This does not seem to be a short MXC URI. Contains : or /. \
                Skipping {:?}. This will likely cause a failure later.",
                vecstr[i]
            );
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
            error!(
                "This user id {:?} starts with an exclamation mark. \
                ! are used for rooms, not users. This will fail later.",
                el
            );
            continue;
        }
        if el.starts_with('#') {
            error!(
                "This user id {:?} starts with a hash tag.
            # are used for room aliases, not users. This will fail later.",
                el
            );
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
            warn!(
                "This room alias {:?} starts with an exclamation mark. \
                ! are used for rooms ids, not aliases. This might cause problems later.",
                el
            );
            continue;
        }
        if el.starts_with('@') {
            error!(
                "This room alias {:?} starts with an at sign. \
                @ are used for user ids, not aliases. This will fail later.",
                el
            );
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
            warn!(
                "This room alias {:?} starts with an exclamation mark. \
                ! are used for rooms ids, not aliases. This might cause problems later.",
                el
            );
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
        let mut credentialsfiltered = credentials.clone();
        credentialsfiltered.access_token = "***".to_string();
        debug!(
            "restore_credentials: loaded credentials are: {:?}",
            credentialsfiltered
        );
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

    // let session: matrix_sdk::SessionMeta = credentials.clone().into();
    let client = create_client(&homeserver, ap).await?;

    // let auth = client.matrix_auth();
    // debug!("Called matrix_auth()");
    // debug!("matrix_auth() successful");

    let msession = MatrixSession {
        meta: SessionMeta {
            user_id: credentials.user_id.clone(),
            device_id: credentials.device_id.clone(),
        },
        tokens: SessionTokens {
            access_token: credentials.access_token.clone(),
            refresh_token: None,
        },
    };

    let res = client.restore_session(msession.clone()).await;
    match res {
        Ok(_) => {
            debug!("restore_session() successful.");
            debug!(
                "Logged in as {}, got device_id {} and access_token {}",
                msession.clone().meta.user_id,
                msession.clone().meta.device_id,
                msession.clone().tokens.access_token,
            );
        }
        Err(e) => {
            error!(
                "Error: Login failed because restore_session() failed. \
                Error: {}",
                e
            );
            return Err(Error::LoginFailed);
        }
    }

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
    // we need to log in.
    let response = client
        .matrix_auth()
        .login_username(username, password)
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
    let _ = client
        .session()
        .expect("Error: client not logged in correctly. No session.");
    info!("device id = {}", client.session_meta().unwrap().device_id);
    info!("credentials file = {:?}", ap.credentials);

    let credentials = Credentials::new(
        homeserver.clone(),
        client.session_meta().unwrap().user_id.clone(),
        client.access_token().unwrap(),
        client.session_meta().unwrap().device_id.clone(),
        room_default.to_string(),
        if let Some(refresh_token) = client.session().unwrap().get_refresh_token() {
            Some(refresh_token.to_string())
        } else {
            None
        }
    );
    credentials.save(&ap.credentials)?;
    // sync is needed even when --login is used,
    // because after --login argument, arguments like -m or --rooms might
    // be used, e.g. in the login-fire-off-a-msg-and-forget scenario
    if ap.listen == Listen::Never {
        sync_once(&client, ap.timeout, ap.sync).await?;
    } else {
        info!("Skipping sync due to --listen");
    }
    Ok((client, credentials))
}

/// Prepares a client that can then be used for actual login.
/// Configures the matrix-sdk async Client.
async fn create_client(homeserver: &Url, ap: &Args) -> Result<Client, Error> {
    // The location to save files to
    let sqlitestorehome = &ap.store;
    debug!(
        "Compare store names: {:?} {:?}",
        ap.store,
        get_store_default_path()
    );
    info!("Using sqlite store {:?}", &sqlitestorehome);
    // let builder = if let Some(proxy) = cli.proxy { builder.proxy(proxy) } else { builder };
    let builder = Client::builder()
        .homeserver_url(homeserver)
        .store_config(StoreConfig::new("".to_string()))
        .request_config(
            RequestConfig::new()
                .timeout(Duration::from_secs(ap.timeout)),
        );
    let client = builder
        .sqlite_store(sqlitestorehome, None)
        .build()
        .await
        .expect("Error: ClientBuilder build failed. Error: cannot add store to ClientBuilder."); // no password for store!
    Ok(client)
}

/// Does bootstrap cross signing
pub(crate) async fn bootstrap(client: &Client, ap: &mut Args) -> Result<(), Error> {
    let userid = &ap.creds.as_ref().unwrap().user_id.clone();
    get_password(ap);
    if let Some(password) = &ap.password {
        let mut css = client.encryption().cross_signing_status().await;
        debug!("Client cross signing status before: {:?}", css);

        if let Err(e) = client.encryption().bootstrap_cross_signing(None).await {
            if let Some(response) = e.as_uiaa_response() {
                let mut password = uiaa::Password::new(
                    uiaa::UserIdentifier::UserIdOrLocalpart(userid.to_string()),
                    password.to_owned(),
                );
                password.session = response.session.clone();

                // Note, on the failed attempt we can use `bootstrap_cross_signing` immediately, to
                // avoid checks.
                debug!("Called bootstrap cross signing {:?}", password.session);
                client
                    .encryption()
                    .bootstrap_cross_signing(Some(uiaa::AuthData::Password(password)))
                    .await
                    .expect("Error: Couldn't bootstrap cross signing.")
            } else {
                error!("Error: {:?}", e);
                return Err(Error::BootstrapFailed);
            }
        }
        css = client.encryption().cross_signing_status().await;
        debug!(
            "bootstrap_cross_signing() was either successful or the cross signing keys were \
            already available in which case nothing is done and password was ignored."
        );
        debug!("Client cross signing status after bootstrapping: {:?}", css);
        Ok(())
    } else {
        Err(Error::MissingPassword)
    }
}

/// Does verification
pub(crate) async fn verify(client: &Client, ap: &Args) -> Result<(), Error> {
    let userid = &ap.creds.as_ref().unwrap().user_id.clone();
    let deviceid = &ap.creds.as_ref().unwrap().device_id.clone();
    debug!("Client active: {}", client.is_active());
    debug!("Client user id: {}", userid);
    debug!("Client device id: {}", deviceid);
    debug!(
        "Client access token used: {:?}",
        obfuscate(&client.access_token().unwrap(), 4)
    );

    let css = client.encryption().cross_signing_status().await;
    debug!("Client cross signing status {:?}", css);
    if let Some(cssc) = css {
        if !cssc.has_self_signing {
            warn!(
                "Client cross signing status is false. Verify is likely to fail. \
                Try running --bootstrap first. {:?}",
                cssc
            );
        }
    }

    if ap.verify.is_manual_user() {
        debug!("Will attempt to verify users '{:?}'.", ap.user);
        let mut errcount = 0;
        for userid in ap.user.clone() {
            match UserId::parse(userid.clone()) {
                Ok(uid) => match client.encryption().get_user_identity(&uid).await {
                    Ok(user) => {
                        if let Some(user) = user {
                            match user.verify().await {
                                Ok(()) => {
                                    info!(
                                        "Successfully verified user {:?} in one direction.",
                                        userid
                                    )
                                }
                                Err(e) => {
                                    error!(
                                        "Error: verify failed. Are you logged in? User exists? \
                                        Do you have cross-signing keys available? {:?} {:?}",
                                        userid, e
                                    );
                                    errcount += 1;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Error: {:?}", e);
                        errcount += 1;
                    }
                },
                Err(e) => {
                    error!("Error: invalid user id {:?}, Error: {:?}", userid, e);
                    errcount += 1;
                }
            }
        }
        if errcount > 0 {
            return Err(Error::VerifyFailed);
        }
    } else if ap.verify.is_manual_device() {
        let response = client.devices().await?;
        for device in response.devices {
            let deviceid = device.device_id;

            match client.encryption().get_device(userid, &deviceid).await {
                Ok(device) => {
                    if let Some(device) = device {
                        match device.verify().await {
                            Ok(()) => info!(
                                "Successfully verified device {:?} in one direction.",
                                deviceid
                            ),
                            Err(e) => {
                                error!(
                                    "Error: verify failed. Are you logged in? Device is yours? \
                                    Do you have cross-signing keys available? {:?} {:?}",
                                    deviceid, e
                                );
                                return Err(Error::VerifyFailed);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Error: {:?}", e);
                    return Err(Error::VerifyFailed);
                }
            }
        }
    } else if ap.verify.is_emoji() {
        emoji_verify::sync_wait_for_verification_request(client).await?; // wait in sync for other party to initiate emoji verify
    } else if ap.verify.is_emoji_req() {
        if ap.user.len() != 1 {
            error!(
                "Error: for requesting verification exactly 1 user must be specified with --user. Found {:?}.",
                ap.user
            )
        } else {
            match &ap.device {
                None => error!(
                    "Error: for requesting verification exactly 1 device must be specified with --device. Found {:?}.",
                    ap.device
                ),
                Some(device) => {
                    emoji_verify::sync_request_verification(client, ap.user[0].to_string(), device.to_string()).await?;
                    // request verification from other device
                }
            }
        }
    } else {
        error!(
            "Error: {:?}",
            Error::UnsupportedCliParameter("Option used for --verify is not supported.")
        );
        return Err(Error::VerifyFailed);
    }
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
            Ok(()) => info!(
                "Credentials file successfully removed {:?}",
                &ap.credentials
            ),
            Err(e) => error!(
                "Error: credentials file not removed. {:?} {:?}",
                &ap.credentials, e
            ),
        }
    } else {
        warn!("Credentials file does not exist {:?}", &ap.credentials)
    }
    match fs::remove_dir_all(&ap.store) {
        Ok(()) => info!("Store directory successfully remove {:?}", &ap.store),
        Err(e) => error!(
            "Error: Store directory not removed. {:?} {:?}",
            &ap.store, e
        ),
    }
    Ok(())
}

/// Only logs out from server, no local changes.
pub(crate) async fn logout_server(client: &Client, ap: &Args) -> Result<(), Error> {
    if ap.logout.is_me() {
        match client.matrix_auth().logout().await {
            Ok(n) => info!("Logout sent to server {:?}", n),
            Err(e) => error!(
                "Error: Server logout failed but we remove local device id anyway. {:?}",
                e
            ),
        }
    }
    if ap.logout.is_all() {
        debug!(
            "Did nothing on server side. \
            All devices should have been deleted already. \
            Check the log a few lines up."
        );
    }
    Ok(())
}

// Todo: when is this sync() really necessary? send seems to work without,
// listen do not need it, devices does not need it but forces it to consume msgs, ...
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
        print_json(
            &json::object!(avatar_mxc_uri: mxc_uri.to_string()),
            output,
            false,
        );
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
            image,
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
            false,
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
    if client.account().set_avatar_url(Some(mxc_uri)).await.is_ok() {
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
    if client.account().set_avatar_url(None).await.is_ok() {
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
        print_json(&json::object!(display_name: name), output, false);
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
    if client.account().set_display_name(Some(name)).await.is_ok() {
        debug!("Display name set successfully.",);
        Ok(())
    } else {
        Err(Error::SetDisplaynameFailed)
    }
}

/// Get profile of the current user.
pub(crate) async fn get_profile(client: &Client, output: Output) -> Result<(), Error> {
    debug!("Get profile from server");
    if let Ok(profile) = client.account().fetch_user_profile().await {
        debug!("Profile successfully. Profile {:?}", profile);
        print_json(
            &json::object!(display_name: profile.get_static::<DisplayName>()?, avatar_url: profile.get_static::<AvatarUrl>()?.as_ref().map(|x| x.as_str())),
            output,
            false,
        );
        Ok(())
    } else {
        Err(Error::GetProfileFailed)
    }
}

fn obfuscate(text: &str, count: usize) -> String {
    let s = text.chars();
    let mut head: String = s.into_iter().take(count).collect::<String>();
    head.push_str("****");
    head.clone()
}

/// Get masterkey of the current user.
/// See: https://docs.rs/matrix-sdk/0.7.1/matrix_sdk/encryption/identities/struct.UserIdentity.html#method.master_key
pub(crate) async fn get_masterkey(
    client: &Client,
    userid: OwnedUserId,
    output: Output,
) -> Result<(), Error> {
    debug!("Get masterkey");

    match client.encryption().get_user_identity(&userid).await {
        Ok(Some(user)) => {
            // we fetch the first public key we
            // can find, there's currently only a single key allowed so this is
            // fine.
            match user.master_key().get_first_key().map(|k| k.to_base64()) {
                Some(masterkey) => {
                    debug!(
                        "get_masterkey obtained masterkey successfully. \
                        Masterkey {:?} (Obfuscated for privacy)",
                        obfuscate(&masterkey, 4)
                    );
                    print_json(&json::object!(masterkey: masterkey), output, true);
                    Ok(())
                }
                None => {
                    error!("No masterkey available user {:?}", userid);
                    Err(Error::GetMasterkeyFailed)
                }
            }
        }
        Ok(None) => {
            error!("Error: user identity for user {:?} not found.", userid);
            Err(Error::GetMasterkeyFailed)
        }
        Err(e) => {
            error!(
                "Error: getting user identity for user {:?} failed. Error: {:?}",
                userid, e
            );
            Err(Error::GetMasterkeyFailed)
        }
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
        let room_id = match RoomId::parse(roomstr.replace("\\!", "!")) {
            // remove possible escape
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
/// Sometimes private sensitive data is being printed.
/// To avoid printing private keys or passwords, set obfuscated to true.
pub(crate) fn print_json(json_data: &json::JsonValue, output: Output, obfuscate: bool) {
    if obfuscate {
        debug!("Skipping printing this object due to privacy.")
    } else {
        debug!("{:?}", json_data);
    }
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
                    print_json(val, output, obfuscate);
                } else if val.is_boolean() {
                    print!("    {}", val);
                } else if val.is_null() {
                    print!("    "); // print nothing
                } else if val.is_string() || val.is_number() {
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
pub(crate) fn print_common_room(room: &room::Room, output: Output) {
    debug!("common room: {:?}", room);
    match output {
        Output::Text => println!(
            "Room:    {:?}    {}    {:?}    {}    {:?}    {:?}",
            room.room_id(),
            serde_json::to_string(&room.clone_info().room_type())
                .unwrap_or_else(|_| r#""""#.to_string()), // serialize, empty string as default
            room.canonical_alias()
                .map_or(r#""#.to_string(), |v| v.to_string()),
            serde_json::to_string(&room.alt_aliases()).unwrap_or_else(|_| r#"[]"#.to_string()), // serialize, empty array as default
            room.name().unwrap_or_default(),
            room.topic().unwrap_or_default(),
            // room.display_name() // this call would go to the server
        ),
        Output::JsonSpec => (),
        _ => {
            // println!(
            //                 "{{\"room_id\": {:?}, \"room_type\": {}, \"canonical_alias\": {:?}, \"alt_aliases\": {}, \"name\": {:?}, \"topic\": {:?}}}",
            //                 room.room_id(),
            //                 serde_json::to_string(&room.clone_info().room_type()).unwrap_or_else(|_| r#""""#.to_string()), // serialize, empty string as default
            //                 room.canonical_alias().map_or(r#""#.to_string(),|v|v.to_string()),
            //                 serde_json::to_string(&room.alt_aliases()).unwrap_or_else(|_| r#"[]"#.to_string()), // serialize, empty array as default
            //                 room.name().unwrap_or_default(),
            //                 room.topic().unwrap_or_default(),
            //             );
            #[derive(serde::Serialize)]
            struct MyRoom<'a> {
                room_id: &'a str,
                room_info: &'a matrix_sdk::RoomInfo,
                alt_aliases: Vec<OwnedRoomAliasId>,
            }
            let myroom = MyRoom {
                room_id: room.room_id().as_str(),
                room_info: &room.clone_info(),
                alt_aliases: room.alt_aliases(),
            };
            let jsonstr = serde_json::to_string(&myroom).unwrap();
            println!("{}", jsonstr);
        }
    }
}

/// Utility function to print Common room info of multiple rooms
pub(crate) fn print_common_rooms(rooms: Vec<room::Room>, output: Output) {
    debug!("common rooms: {:?}", rooms);
    match output {
        Output::Text => {
            for r in rooms {
                print_common_room(&r, output)
            }
        }
        Output::JsonSpec => (),
        _ => {
            #[derive(serde::Serialize)]
            struct MyRoom<'a> {
                room_id: &'a str,
                room_info: matrix_sdk::RoomInfo,
                alt_aliases: Vec<OwnedRoomAliasId>,
            }
            let mut myrooms: Vec<MyRoom> = Vec::new();
            let mut myroom: MyRoom;
            for r in &rooms {
                myroom = MyRoom {
                    room_id: r.room_id().as_str(),
                    room_info: r.clone_info(),
                    alt_aliases: r.alt_aliases(),
                };
                myrooms.push(myroom);
            }
            let jsonstr = serde_json::to_string(&myrooms).unwrap();
            println!("{}", jsonstr);
            // to list only room ids run a comand like matrix-commander-rs --rooms --output json | jq '.[].room_id'
        }
    }
}

/// Print list of rooms of a given type (invited, joined, left, all) of the current user.
pub(crate) fn print_rooms(
    client: &Client,
    rooms: Option<matrix_sdk::RoomState>, // None is the default and prints all 3 types of rooms
    output: Output,
) -> Result<(), Error> {
    debug!("Rooms (local)");
    match rooms {
        None => {
            // ALL rooms, default
            print_common_rooms(client.rooms(), output);
        }
        Some(matrix_sdk::RoomState::Invited) => {
            print_common_rooms(client.invited_rooms(), output);
        }
        Some(matrix_sdk::RoomState::Joined) => {
            print_common_rooms(client.joined_rooms(), output);
        }
        Some(matrix_sdk::RoomState::Left) => {
            print_common_rooms(client.left_rooms(), output);
        }
        Some(matrix_sdk::RoomState::Knocked) | Some(matrix_sdk::RoomState::Banned) => (),
        /*Some(matrix_sdk::RoomState::Knocked) => {
            print_common_rooms(client.knocked_rooms(), output);
        }
        Some(matrix_sdk::RoomState::Banned) => {
            print_common_rooms(client.banned_rooms(), output);
        }*/
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
    print_rooms(client, Some(matrix_sdk::RoomState::Invited), output)
}

/// Print list of all joined rooms (not invited, not left) of the current user.
pub(crate) async fn joined_rooms(client: &Client, output: Output) -> Result<(), Error> {
    debug!("Joined_rooms (local)");
    print_rooms(client, Some(matrix_sdk::RoomState::Joined), output)
}

/// Print list of all left rooms (not invited, not joined) of the current user.
pub(crate) async fn left_rooms(client: &Client, output: Output) -> Result<(), Error> {
    debug!("Left_rooms (local)");
    print_rooms(client, Some(matrix_sdk::RoomState::Left), output)
}

/// Create rooms, either normal room or DM room:
/// For normal room, create one room for each alias name in the list.
/// For DM room, create one DM room for each user name in the list.
/// Alias name can be empty, i.e. ''.
/// If and when available set the room name from the name list.
/// If and when available set the topic name from the topic list.
/// As output it lists/prints the newly generated room ids and and the corresponding room aliases.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn room_create(
    client: &Client,
    is_dm: bool,             // is DM room
    is_encrypted: bool,      // create an encrypted room or not
    users: &[String],        // users, only useful for DM rooms
    room_aliases: &[String], // list of simple alias names like 'SomeAlias', not full aliases
    names: &[String],        // list of room names, optional
    room_topics: &[String],  // list of room topics, optional
    output: Output,          // how to format output
    visibility: Visibility,  // visibility of the newly created room
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
            let initstateev: InitialStateEvent<RoomEncryptionEventContent> = InitialStateEvent::new(
                EmptyStateKey,
                content,
            );
            let rawinitstateev = Raw::new(&initstateev)?;
            // let anyinitstateev: AnyInitialStateEvent =
            //     matrix_sdk::ruma::events::AnyInitialStateEvent::RoomEncryption(initstateev);
            // todo: better alternative? let anyinitstateev2: AnyInitialStateEvent = AnyInitialStateEvent::from(initstateev);

            let rawanyinitstateev: Raw<AnyInitialStateEvent> = rawinitstateev.cast();
            initstateevvec.push(rawanyinitstateev);
            request.initial_state = initstateevvec;
        }

        request.name = Some(names2[i].clone());
        request.room_alias_name = Some(aliases2[i].clone()).filter(|s| !s.is_empty());
        request.topic = Some(topics2[i].clone());
        request.is_direct = is_dm;
        let usr: OwnedUserId;
        let mut invites = vec![];
        if is_dm {
            usr = match UserId::parse(<std::string::String as AsRef<str>>::as_ref(
                &users2[i].replace("\\@", "@"),
            )) {
                // remove possible escape
                Ok(u) => u,
                Err(ref e) => {
                    err_count += 1;
                    i += 1;
                    error!(
                        "Error: create_room failed, because user for DM is not valid, \
                        reported error {:?}.",
                        e
                    );
                    continue;
                }
            };
            invites.push(usr);
            request.invite = invites;
            // Visibility defaults to "Private" by matrix-sdk API, so "Private" for both normal rooms and DM rooms.
            request.visibility = visibility.clone();
            request.preset = match visibility {
                Visibility::Public => {
                    warn!(
                        "Creating a public room for a DM user is not allowed. Setting to private."
                    );
                    Some(RoomPreset::PrivateChat)
                }
                Visibility::Private => Some(RoomPreset::PrivateChat),
                _ => None,
            };
        } else {
            request.visibility = visibility.clone();
            request.preset = match visibility {
                Visibility::Public => {
                    info!(
                        "Creating a public {} room.",
                        if is_encrypted {
                            "encrypted"
                        } else {
                            "unencrypted"
                        }
                    );
                    Some(RoomPreset::PublicChat)
                }
                Visibility::Private => {
                    info!(
                        "Creating a private {} room.",
                        if is_encrypted {
                            "encrypted"
                        } else {
                            "unencrypted"
                        }
                    );
                    Some(RoomPreset::PrivateChat)
                }
                _ => None,
            };
        }
        match client.create_room(request).await {
            Ok(created_room) => {
                debug!("create_room succeeded, result is {:?}.", created_room);
                print_json(
                    &json::object!(
                        room_id: created_room.room_id().to_string(),
                        alias: to_opt(&aliases2[i]),
                        name: to_opt(&names2[i]),
                        topic: to_opt(&topics2[i]),
                        invited: <std::string::String as AsRef<str>>::as_ref(&users2[i]),
                        direct: created_room.is_direct().await.unwrap_or(is_dm),
                        encrypted: format!("{:?}", created_room.encryption_state()),
                        visibility: if created_room.is_public().unwrap() {
                            "Public"
                        } else {
                            "Private"
                        },
                    ),
                    output,
                    false,
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
        roomids.push(match RoomId::parse(room_id.clone().replace("\\!", "!")) {
            //remove possible escape
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
        let jroomopt = client.get_room(id);
        match jroomopt {
            Some(jroom) => match jroom.leave().await {
                Ok(_) => {
                    info!("Left room {:?} successfully.", id);
                    // Todo: does this work? Does not seem to work.
                    jroom.clone_info().mark_as_left();
                }
                Err(ref e) => {
                    error!("Error: leave() returned error {:?}.", e);
                    err_count += 1;
                }
            },
            None => {
                error!(
                    "Error: get_room() returned error. Only invited and joined rooms can be left."
                );
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
        roomids.push(match RoomId::parse(room_id.clone().replace("\\!", "!")) {
            // remove possible escape
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
        let jroomopt = client.get_room(id);
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
                error!(
                    "Error: get_room() returned error. Have you been a member of \
                    this room? Have you left this room before? \
                    Leave the room before forgetting it."
                );
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
            match RoomId::parse(<std::string::String as AsRef<str>>::as_ref(
                &room_id.replace("\\!", "!"),
            )) {
                // remove possible escapes
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
            match UserId::parse(<std::string::String as AsRef<str>>::as_ref(
                &user_id.replace("\\@", "@"),
            )) {
                // remove possible escape
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
        let jroomopt = client.get_room(id);
        match jroomopt {
            Some(jroom) => {
                for u in &userids {
                    match jroom.invite_user_by_id(u).await {
                        Ok(_) => {
                            info!("Invited user {:?} to room {:?} successfully.", u, id);
                        }
                        Err(ref e) => {
                            error!(
                                "Error: failed to invited user {:?} to room {:?}. \
                                invite_user_by_id() returned error {:?}.",
                                u, id, e
                            );
                            err_count += 1;
                        }
                    }
                }
            }
            None => {
                error!(
                    "Error: get_room() returned error. \
                    Are you a member of this room ({:?})? \
                    Join the room before inviting others to it.",
                    id
                );
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
            match RoomId::parse(<std::string::String as AsRef<str>>::as_ref(
                &room_id.replace("\\!", "!"),
            )) {
                // remove possible escape
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
            match RoomId::parse(<std::string::String as AsRef<str>>::as_ref(
                &room_id.replace("\\!", "!"),
            )) {
                // remove possible escape
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
            match UserId::parse(<std::string::String as AsRef<str>>::as_ref(
                &user_id.replace("\\!", "!"),
            )) {
                // remove possible escape
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
        let jroomopt = client.get_room(id);
        match jroomopt {
            Some(jroom) => {
                for u in &userids {
                    match jroom.ban_user(u, None).await {
                        Ok(_) => {
                            info!("Banned user {:?} from room {:?} successfully.", u, id);
                        }
                        Err(ref e) => {
                            error!(
                                "Error: failed to ban user {:?} from room {:?}. \
                                ban_user() returned error {:?}.",
                                u, id, e
                            );
                            err_count += 1;
                        }
                    }
                }
            }
            None => {
                error!(
                    "Error: get_room() returned error. Are you a member of this room ({:?})? \
                    Join the room before banning others from it.",
                    id
                );
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
            match RoomId::parse(<std::string::String as AsRef<str>>::as_ref(
                &room_id.replace("\\!", "!"),
            )) {
                // remove possible escape
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
            match UserId::parse(<std::string::String as AsRef<str>>::as_ref(
                &user_id.replace("\\@", "@"),
            )) {
                // remove possible escape
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
        let jroomopt = client.get_room(id);
        match jroomopt {
            Some(jroom) => {
                for u in &userids {
                    match jroom.kick_user(u, None).await {
                        Ok(_) => {
                            info!("Kicked user {:?} from room {:?} successfully.", u, id);
                        }
                        Err(ref e) => {
                            error!(
                                "Error: failed to kick user {:?} from room {:?}. \
                                kick_user() returned error {:?}.",
                                u, id, e
                            );
                            err_count += 1;
                        }
                    }
                }
            }
            None => {
                error!(
                    "Error: get_room() returned error. Are you a member of this room ({:?})? \
                    Join the room before kicking others from it.",
                    id
                );
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
                if room.is_public().unwrap() {
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
                room.is_public().unwrap()
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
            match RoomId::parse(<std::string::String as AsRef<str>>::as_ref(
                &room_id.replace("\\!", "!"),
            )) {
                // remove possible escape
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
    let member_evs = room
        .get_state_events_static::<RoomMemberEventContent>()
        .await?;
    let power_level_evs = room
        .get_state_events_static::<RoomPowerLevelsEventContent>()
        .await?;
    let name_evs = room
        .get_state_events_static::<RoomNameEventContent>()
        .await?;
    let topic_evs = room
        .get_state_events_static::<RoomTopicEventContent>()
        .await?;

    match output {
        Output::Text => {
            print!(
                "Room:    \"{}\",\n\
                 RoomMemberEventContent: [{}],\n\
                 RoomPowerLevelsEventContent: [{}],\n\
                 RoomNameEventContent: [{}],\n\
                 RoomTopicEventContent: [{}]\n",
                room_id,
                member_evs
                    .iter()
                    .map(|value| format!("{:?}", value.deserialize()))
                    .collect::<Vec<String>>()
                    .join(", "),
                power_level_evs
                    .iter()
                    .map(|value| format!("{:?}", value.deserialize()))
                    .collect::<Vec<String>>()
                    .join(", "),
                name_evs
                    .iter()
                    .map(|value| format!("{:?}", value.deserialize()))
                    .collect::<Vec<String>>()
                    .join(", "),
                topic_evs
                    .iter()
                    .map(|value| format!("{:?}", value.deserialize()))
                    .collect::<Vec<String>>()
                    .join(", "),
            );
        }
        // Output::JsonSpec => (), // These events should be spec compliant
        _ => {
            use matrix_sdk::deserialized_responses::RawSyncOrStrippedState;
            #[derive(serde::Serialize)]
            struct MyState<'a> {
                room_id: &'a str,
                room_member_event_content: Vec<RawSyncOrStrippedState<RoomMemberEventContent>>,
                room_power_levels_event_content:
                    Vec<RawSyncOrStrippedState<RoomPowerLevelsEventContent>>,
                room_name_event_content: Vec<RawSyncOrStrippedState<RoomNameEventContent>>,
                room_topic_event_content: Vec<RawSyncOrStrippedState<RoomTopicEventContent>>,
            }
            let mystate = MyState {
                room_id: room_id.as_str(),
                room_member_event_content: member_evs,
                room_power_levels_event_content: power_level_evs,
                room_name_event_content: name_evs,
                room_topic_event_content: topic_evs,
            };
            let jsonstr = serde_json::to_string(&mystate).unwrap();
            println!("{}", jsonstr);
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
            match RoomId::parse(<std::string::String as AsRef<str>>::as_ref(
                &room_id.replace("\\!", "!"),
            )) {
                // remove possible escape
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
                    "Room:    {:?}    Member:    {:?}    {:?}    {:?}    {:?}    {:?}    \"{}\"",
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
            #[derive(serde::Serialize, serde::Deserialize)]
            struct MyMember<'a> {
                user_id: &'a str,
                display_name: &'a str,
                name: &'a str,
                avatar_url: &'a str,
                //power_level: UserPowerLevel,
                //power_level: MyUserPowerLevel,
                membership: &'a str,
            }
            /*#[derive(serde::Serialize, serde::Deserialize)]
            struct MyUserPowerLevel<'a> {
                power_level: UserPowerLevel,
            }*/
            #[derive(serde::Serialize, serde::Deserialize)]
            struct MyRoom<'a> {
                room_id: &'a str,
                members: Vec<MyMember<'a>>,
            }
            let mut mymembers: Vec<MyMember> = Vec::new();
            for m in members {
                let mymember = MyMember {
                    user_id: m.user_id().as_str(),
                    display_name: m.display_name().unwrap_or(""),
                    name: m.name(),
                    avatar_url: m.avatar_url().unwrap_or("".into()).as_str(),
                    //power_level: m.power_level(),
                    membership: m.membership().as_str(),
                };
                mymembers.push(mymember);
            }
            let myroom = MyRoom {
                room_id: room_id.as_str(),
                members: mymembers,
            };
            let jsonstr = serde_json::to_string(&myroom).unwrap();
            println!("{}", jsonstr);
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
            match RoomId::parse(<std::string::String as AsRef<str>>::as_ref(
                &room_id.replace("\\!", "!"),
            )) {
                //remove possible escape
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
            Some(r) => match r.members(RoomMemberships::JOIN).await {
                Ok(ref m) => {
                    debug!("Members of room {:?} are {:?}.", id, m);
                    print_room_members(id, m, output);
                }
                Err(ref e) => {
                    error!(
                        "Error: failed to get members of room {:?}. \
                        members() returned error {:?}.",
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
        aliasids.push(
            match RoomAliasId::parse(alias_id.clone().replace("\\#", "#")) {
                // remove possible escape
                Ok(id) => id,
                Err(ref e) => {
                    error!(
                        "Error: invalid alias id {:?}. Error reported is {:?}.",
                        alias_id, e
                    );
                    continue;
                }
            },
        );
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
            match RoomId::parse(<std::string::String as AsRef<str>>::as_ref(
                &room_id.replace("\\!", "!"),
            )) {
                // remove possible escape
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
    // without sync() client will not know that it is in joined rooms list and it will fail,
    // we must sync!
    // client.sync_once(SyncSettings::new()).await?; we should have sync-ed before.
    for (i, id) in roomids.iter().enumerate() {
        debug!("In position {} we have room id {:?}.", i, id,);
        match client.get_room(id) {
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
                error!(
                    "get_room failed for room {:?}, \
                    Are you member of this room? \
                    If you are member of this room try syncing first.",
                    id
                );
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
    if let Some(user) = ap.user.first() {
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
            // hide password from debug log file
            debug!(
                "Preparing to delete these devices for user {:?} with password {:?}: {:?}",
                user, "******", ap.delete_device
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
    // hide password from debug log file
    debug!(
        "About to delete these devices of user {:?} with password {:?}: {:?}",
        user, "******", deviceids
    );
    if let Err(e) = client.delete_devices(&deviceids, None).await {
        if let Some(info) = e.as_uiaa_response() {
            let mut password = uiaa::Password::new(
                // full user id (@john:some.matrix.org), or just local part (john)
                uiaa::UserIdentifier::UserIdOrLocalpart(user.to_string()),
                password.to_string(),
            );
            password.session = info.session.clone();

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
    html: bool,
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
            } else if html {
                NoticeMessageEventContent::html(nmsg, nmsg)
            } else {
                NoticeMessageEventContent::plain(nmsg)
            })
        } else if emote {
            MessageType::Emote(if md {
                EmoteMessageEventContent::markdown(nmsg)
            } else if html {
                EmoteMessageEventContent::html(nmsg, nmsg)
            } else {
                EmoteMessageEventContent::plain(nmsg)
            })
        } else {
            MessageType::Text(if md {
                TextMessageEventContent::markdown(nmsg)
            } else if html {
                TextMessageEventContent::html(nmsg, nmsg)
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
        let proom = RoomId::parse(roomname.replace("\\!", "!")).unwrap(); // remove possible escape
        debug!("In message(): parsed room name is {:?}", proom);
        let room = client.get_room(&proom).ok_or(Error::InvalidRoom)?;
        for fmsg in fmsgs.iter() {
            match room.send(RoomMessageEventContent::new(fmsg.clone())).await {
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
        let proom = RoomId::parse(roomname.replace("\\!", "!")).unwrap(); // remove possible escape
        debug!("In file(): parsed room name is {:?}", proom);
        let room = client.get_room(&proom).ok_or(Error::InvalidRoom)?;
        for mut filename in filenames.iter() {
            let data = if filename.to_str().unwrap() == "-" {
                // read from stdin
                let mut buffer = Vec::new();
                if stdin().is_terminal() {
                    print!("Waiting for data to be piped into stdin. Enter data now: ");
                    std::io::stdout().flush()?;
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
                        data,
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
                    error!(
                        "Provided Mime {:?} is not valid; the upload of file {:?} \
                        will be skipped; returned error {:?}",
                        mime_str, filename, e
                    );
                    err_count += 1;
                    i += 1;
                    continue;
                }
            }
        }

        let data = if filename.to_str().unwrap() == "-" {
            // read from stdin
            let mut buffer = Vec::new();
            if stdin().is_terminal() {
                eprint!("Waiting for data to be piped into stdin. Enter data now: ");
                std::io::stdout().flush()?;
            }
            // read the whole file
            io::stdin().read_to_end(&mut buffer)?;
            buffer
        } else {
            if filename.to_str().unwrap() == r"\-" {
                filename = PathBuf::from(r"-");
            }
            fs::read(&filename).unwrap_or_else(|e| {
                error!(
                    "File {:?} was not found; the upload of file {:?} \
                    will be skipped; returned error {:?}",
                    filename, filename, e
                );
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
            match client.media().upload(&mime, data, None).await {
                Ok(response) => {
                    debug!("upload successful {:?}", response);
                    print_json(
                        &json::object!(file_name: filename.to_str(),
                        upload_mxc_uri: response.content_uri.as_str(),
                        mime: mime.to_string()),
                        output,
                        false,
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
        let request = MediaRequestParameters {
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
                                false,
                            );
                        }
                        Err(ref e) => {
                            error!(
                                "The downloaded media data could not be written to stdout. \
                                write() returned error {:?}",
                                e
                            );
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
                                false,
                            );
                        }
                        Ok(Err(ref e)) => {
                            error!(
                                "Writing downloaded media to file {:?} failed. \
                                Error returned is {:?}",
                                filename, e
                            );
                            err_count += 1;
                        }
                        Err(ref e) => {
                            error!(
                                "Could not create file {:?} for storing downloaded media. \
                                Returned error {:?}.",
                                filename, e
                            );
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
                    false,
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
