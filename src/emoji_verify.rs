//
// https://www.github.com/8go/matrix-commander-rs
// emoji_verify.rs
//

//! Module that bundles everything together do to emoji verification for Matrix.
//! It implements the emoji-verification protocol.

use std::io::{self, Write};
use tracing::{debug, info};

// Code for emoji verify
use matrix_sdk::{
    self,
    config::SyncSettings,
    encryption::verification::{format_emojis, SasVerification, Verification},
    ruma::{
        events::{
            key::verification::{
                done::{OriginalSyncKeyVerificationDoneEvent, ToDeviceKeyVerificationDoneEvent},
                key::{OriginalSyncKeyVerificationKeyEvent, ToDeviceKeyVerificationKeyEvent},
                request::ToDeviceKeyVerificationRequestEvent,
                start::{OriginalSyncKeyVerificationStartEvent, ToDeviceKeyVerificationStartEvent},
            },
            room::message::{MessageType, OriginalSyncRoomMessageEvent},
        },
        UserId,
    },
    Client,
};
// local
use crate::get_prog_without_ext;

/// Utility function to get user response interactively. Answer question if emojis match.
/// The event manager calls this function once emoji verification has been initiated.
// The arguments client and sas cannot be borrowed. If borrowed they would go out of scope.
async fn wait_for_confirmation(client: Client, sas: SasVerification) {
    let emoji = sas.emoji().expect("The emojis should be available now.");

    println!("\nDo the emojis match: \n{}", format_emojis(emoji));
    print!("Confirm with `yes` or cancel with `no` or Control-C to abort: ");
    std::io::stdout()
        .flush()
        .expect("We should be able to flush stdout");

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("error: unable to read user input");

    match input.trim().to_lowercase().as_ref() {
        "yes" | "y" | "true" | "ok" => {
            info!("Received 'Yes'!");
            sas.confirm().await.unwrap();

            if sas.is_done() {
                print_devices(sas.other_device().user_id(), &client).await;
                print_result(&sas);
            } else {
                info!("Sas not done yet.");
            }
        }
        _ => {
            info!("Cancelling. Sorry!");
            sas.cancel().await.unwrap();
        }
    }
}

/// Utility function to print confirmed verification results
fn print_result(sas: &SasVerification) {
    let device = sas.other_device();

    println!(
        "Successfully verified device {} {} {:?}",
        device.user_id(),
        device.device_id(),
        device.local_trust_state()
    );

    println!("\nDo more Emoji verifications or hit Control-C to terminate program.\n");
}

/// Utility functions to show all devices of the user and their verification state.
async fn print_devices(user_id: &UserId, client: &Client) {
    info!("Devices of user {}", user_id);

    for device in client
        .encryption()
        .get_user_devices(user_id)
        .await
        .unwrap()
        .devices()
    {
        info!(
            "   {:<10} {:<30} {:<}",
            device.device_id(),
            device.display_name().unwrap_or("-"),
            device.is_verified()
        );
    }
}

/// Go into the event loop and implement the emoji verification protocol.
/// This is the main function, the access point, to emoji verification.
/// Remember it is interactive and will remain in the event loop until user
/// leaves with Control-C.
pub async fn sync(client: &Client) -> matrix_sdk::Result<()> {
    client.add_event_handler(
        |ev: ToDeviceKeyVerificationRequestEvent, client: Client| async move {
            debug!("ToDeviceKeyVerificationRequestEvent");
            let request = client
                .encryption()
                .get_verification_request(&ev.sender, &ev.content.transaction_id)
                .await
                .expect("Request object wasn't created");

            request
                .accept()
                .await
                .expect("Can't accept verification request");
        },
    );

    client.add_event_handler(
        |ev: ToDeviceKeyVerificationStartEvent, client: Client| async move {
            debug!("ToDeviceKeyVerificationStartEvent");
            if let Some(Verification::SasV1(sas)) = client
                .encryption()
                .get_verification(&ev.sender, ev.content.transaction_id.as_str())
                .await
            {
                info!(
                    "Starting verification with {} {}",
                    &sas.other_device().user_id(),
                    &sas.other_device().device_id()
                );
                print_devices(&ev.sender, &client).await;
                sas.accept().await.unwrap();
            }
        },
    );

    client.add_event_handler(
        |ev: ToDeviceKeyVerificationKeyEvent, client: Client| async move {
            debug!("ToDeviceKeyVerificationKeyEvent");
            if let Some(Verification::SasV1(sas)) = client
                .encryption()
                .get_verification(&ev.sender, ev.content.transaction_id.as_str())
                .await
            {
                tokio::spawn(wait_for_confirmation(client, sas));
            }
        },
    );

    client.add_event_handler(
        |ev: ToDeviceKeyVerificationDoneEvent, client: Client| async move {
            debug!("ToDeviceKeyVerificationDoneEvent");
            if let Some(Verification::SasV1(sas)) = client
                .encryption()
                .get_verification(&ev.sender, ev.content.transaction_id.as_str())
                .await
            {
                if sas.is_done() {
                    print_result(&sas);
                    print_devices(&ev.sender, &client).await;
                }
            }
        },
    );

    client.add_event_handler(
        |ev: OriginalSyncRoomMessageEvent, client: Client| async move {
            debug!("OriginalSyncRoomMessageEvent");
            if let MessageType::VerificationRequest(_) = &ev.content.msgtype {
                let request = client
                    .encryption()
                    .get_verification_request(&ev.sender, &ev.event_id)
                    .await
                    .expect("Request object wasn't created");

                request
                    .accept()
                    .await
                    .expect("Can't accept verification request");
            }
        },
    );

    client.add_event_handler(
        |ev: OriginalSyncKeyVerificationStartEvent, client: Client| async move {
            debug!("OriginalSyncKeyVerificationStartEvent");
            if let Some(Verification::SasV1(sas)) = client
                .encryption()
                .get_verification(&ev.sender, ev.content.relates_to.event_id.as_str())
                .await
            {
                println!(
                    "Starting verification with {} {}",
                    &sas.other_device().user_id(),
                    &sas.other_device().device_id()
                );
                print_devices(&ev.sender, &client).await;
                sas.accept().await.unwrap();
            }
        },
    );

    client.add_event_handler(
        |ev: OriginalSyncKeyVerificationKeyEvent, client: Client| async move {
            debug!("OriginalSyncKeyVerificationKeyEvent");
            if let Some(Verification::SasV1(sas)) = client
                .encryption()
                .get_verification(&ev.sender, ev.content.relates_to.event_id.as_str())
                .await
            {
                tokio::spawn(wait_for_confirmation(client, sas));
            }
        },
    );

    client.add_event_handler(
        |ev: OriginalSyncKeyVerificationDoneEvent, client: Client| async move {
            debug!("OriginalSyncKeyVerificationDoneEvent");
            if let Some(Verification::SasV1(sas)) = client
                .encryption()
                .get_verification(&ev.sender, ev.content.relates_to.event_id.as_str())
                .await
            {
                if sas.is_done() {
                    print_result(&sas);
                    print_devices(&ev.sender, &client).await;
                }
            }
        },
    );

    // go into event loop to sync and to execute verify protocol
    println!("Ready and waiting ...");
    println!("Go to other Matrix client like Element and initiate Emoji verification there.");
    println!("Best to have the other Matrix client ready and waiting before you start");
    println!("{}.", get_prog_without_ext());
    client.sync(SyncSettings::new()).await?;

    Ok(())
}
