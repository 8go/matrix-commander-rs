//
// https://www.github.com/8go/matrix-commander-rs
// emoji_verify.rs
//

//! Module that bundles everything together do to emoji verification for Matrix.
//! It implements the emoji-verification protocol.

use std::io::{self, Write};
use tracing::{debug, error, info, warn};

use futures_util::StreamExt;

// Code for emoji verify
use matrix_sdk::{
    self,
    config::SyncSettings,
    encryption::verification::{
        format_emojis, Emoji, SasState, SasVerification, Verification, VerificationRequest,
        VerificationRequestState,
    },
    ruma::{
        events::{
            key::verification::{
                accept::ToDeviceKeyVerificationAcceptEvent,
                cancel::ToDeviceKeyVerificationCancelEvent,
                done::{OriginalSyncKeyVerificationDoneEvent, ToDeviceKeyVerificationDoneEvent},
                key::{OriginalSyncKeyVerificationKeyEvent, ToDeviceKeyVerificationKeyEvent},
                // mac::{ToDeviceKeyVerificationMacEvent},
                ready::ToDeviceKeyVerificationReadyEvent,
                request::ToDeviceKeyVerificationRequestEvent,
                start::OriginalSyncKeyVerificationStartEvent,
                start::ToDeviceKeyVerificationStartEvent,
                VerificationMethod,
            },
            room::message::{MessageType, OriginalSyncRoomMessageEvent, SyncRoomMessageEvent},
        },
        OwnedDeviceId, OwnedUserId, UserId,
    },
    Client,
};
// local
use crate::get_prog_without_ext;

async fn wait_for_confirmation(sas: SasVerification, emoji: [Emoji; 7]) {
    println!("\nDo the emojis match: \n{}", format_emojis(emoji));
    print!("Confirm with `yes` or cancel with `no`: ");
    if let Err(e) = io::stdout().flush() {
        warn!("Warning: Failed to flush stdout: {e}");
    }
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        error!("Error: Unable to read user input. Cancelling.");
        input = "no".to_string(); // cancel
    }
    match input.trim().to_lowercase().as_ref() {
        "yes" | "true" | "ok" => sas.confirm().await.unwrap(),
        _ => sas.cancel().await.unwrap(),
    }
}

/// Utility function to print confirmed verification results
fn print_success(sas: &SasVerification) {
    let device = sas.other_device();

    println!(
        "Successfully verified device {} {}, local trust state: {:?}",
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
            "   {:<10} {:<30} is_verified={:<}",
            device.device_id(),
            device.display_name().unwrap_or("-"),
            device.is_verified()
        );
    }
}

async fn sas_verification_handler(client: Client, sas: SasVerification) {
    println!(
        "Starting verification with {} {}",
        &sas.other_device().user_id(),
        &sas.other_device().device_id()
    );
    print_devices(sas.other_device().user_id(), &client).await;
    sas.accept().await.unwrap();

    let mut stream = sas.changes();

    while let Some(state) = stream.next().await {
        match state.clone() {
            SasState::KeysExchanged {
                emojis,
                decimals: _,
            } => {
                debug!(
                    "sas_verification_handler: state {:?} (SasState::KeysExchanged)",
                    state
                );
                tokio::spawn(wait_for_confirmation(
                    sas.clone(),
                    emojis
                        .expect("Error: We only support verifications using emojis")
                        .emojis,
                ));
            }
            SasState::Done { .. } => {
                debug!(
                    "sas_verification_handler: state {:?} (SasState::Done)",
                    state
                );
                print_success(&sas);
                print_devices(sas.other_device().user_id(), &client).await;
                break;
            }
            SasState::Cancelled(cancel_info) => {
                println!(
                    "The verification has been cancelled, reason: {}",
                    cancel_info.reason()
                );

                break;
            }
            SasState::Started { .. } | SasState::Accepted { .. } | SasState::Confirmed => {
                debug!("sas_verification_handler: state {:?} ignored", state);
            }
            SasState::Created { .. } => todo!()
        }
    }
}

async fn request_verification_handler(client: Client, request: VerificationRequest) {
    println!(
        "Accepting verification request from {}",
        request.other_user_id(),
    );
    request
        .accept()
        .await
        .expect("Error: Can't accept verification request");

    let mut stream = request.changes();

    while let Some(state) = stream.next().await {
        match state.clone() {
            VerificationRequestState::Created { .. }
            | VerificationRequestState::Requested { .. }
            | VerificationRequestState::Ready { .. } => {
                debug!("request_verification_handler: state {:?} ignored", state);
            }
            VerificationRequestState::Transitioned { verification } => {
                // We only support SAS verification.
                debug!(
                    "request_verification_handler: state {:?}, Verification state transitioned.",
                    state
                );
                if let Verification::SasV1(s) = verification {
                    debug!("request_verification_handler: Verification state transitioned to Emoji verification.");
                    tokio::spawn(sas_verification_handler(client, s));
                    break;
                }
            }
            VerificationRequestState::Done | VerificationRequestState::Cancelled(_) => {
                debug!(
                    "request_verification_handler: state {:?} forces us to stop",
                    state
                );
                break;
            }
        }
    }
}

/// Go into the event loop and implement the emoji verification protocol.
/// We are waiting for someone else to request the verification.
/// This is the main function, the access point, to emoji verification.
/// Remember it is interactive and will remain in the event loop until user
/// leaves with Control-C.
pub async fn sync_wait_for_verification_request(client: &Client) -> matrix_sdk::Result<()> {
    client.add_event_handler(
        |ev: ToDeviceKeyVerificationRequestEvent, client: Client| async move {
            debug!("ToDeviceKeyVerificationRequestEvent: entering");
            let request = client
                .encryption()
                .get_verification_request(&ev.sender, &ev.content.transaction_id)
                .await
                .expect("Error: Request object wasn't created");

            tokio::spawn(request_verification_handler(client, request));

            debug!("ToDeviceKeyVerificationRequestEvent: leaving");
        },
    );

    client.add_event_handler(
        |ev: OriginalSyncRoomMessageEvent, client: Client| async move {
            debug!("OriginalSyncRoomMessageEvent: entering");
            if let MessageType::VerificationRequest(_) = &ev.content.msgtype {
                let request = client
                    .encryption()
                    .get_verification_request(&ev.sender, &ev.event_id)
                    .await
                    .expect("Error: Request object wasn't created");

                tokio::spawn(request_verification_handler(client, request));

                debug!("OriginalSyncRoomMessageEvent: leaving");
            }
        },
    );

    // // removed Sept 2024, following matrix-rust-sdk/examples/emoji_verification
    // client.add_event_handler(
    //     |ev: ToDeviceKeyVerificationStartEvent, client: Client| async move {
    //         debug!("ToDeviceKeyVerificationStartEvent");
    //         if let Some(Verification::SasV1(sas)) = client
    //             .encryption()
    //             .get_verification(&ev.sender, ev.content.transaction_id.as_str())
    //             .await
    //         {
    //             info!(
    //                 "Starting verification with {} {}",
    //                 &sas.other_device().user_id(),
    //                 &sas.other_device().device_id()
    //             );
    //             print_devices(&ev.sender, &client).await;
    //             sas.accept().await.unwrap();
    //         }
    //     },
    // );

    // // removed Sept 2024, following matrix-rust-sdk/examples/emoji_verification
    // client.add_event_handler(
    //     |ev: ToDeviceKeyVerificationKeyEvent, client: Client| async move {
    //         debug!("ToDeviceKeyVerificationKeyEvent");
    //         if let Some(Verification::SasV1(sas)) = client
    //             .encryption()
    //             .get_verification(&ev.sender, ev.content.transaction_id.as_str())
    //             .await
    //         {
    //             tokio::spawn(sas_verification_handler(client, sas));
    //         }
    //     },
    // );

    // // removed Sept 2024, following matrix-rust-sdk/examples/emoji_verification
    // client.add_event_handler(
    //     |ev: ToDeviceKeyVerificationDoneEvent, client: Client| async move {
    //         debug!("ToDeviceKeyVerificationDoneEvent");
    //         if let Some(Verification::SasV1(sas)) = client
    //             .encryption()
    //             .get_verification(&ev.sender, ev.content.transaction_id.as_str())
    //             .await
    //         {
    //             if sas.is_done() {
    //                 print_success(&sas);
    //                 print_devices(&ev.sender, &client).await;
    //             }
    //         }
    //     },
    // );

    // // removed Sept 2024, following matrix-rust-sdk/examples/emoji_verification
    // client.add_event_handler(
    //     |ev: OriginalSyncKeyVerificationStartEvent, client: Client| async move {
    //         debug!("OriginalSyncKeyVerificationStartEvent");
    //         if let Some(Verification::SasV1(sas)) = client
    //             .encryption()
    //             .get_verification(&ev.sender, ev.content.relates_to.event_id.as_str())
    //             .await
    //         {
    //             println!(
    //                 "Starting verification with {} {}",
    //                 &sas.other_device().user_id(),
    //                 &sas.other_device().device_id()
    //             );
    //             print_devices(&ev.sender, &client).await;
    //             sas.accept().await.unwrap();
    //         }
    //     },
    // );

    // // removed Sept 2024, following matrix-rust-sdk/examples/emoji_verification
    // client.add_event_handler(
    //     |ev: OriginalSyncKeyVerificationKeyEvent, client: Client| async move {
    //         debug!("OriginalSyncKeyVerificationKeyEvent");
    //         if let Some(Verification::SasV1(sas)) = client
    //             .encryption()
    //             .get_verification(&ev.sender, ev.content.relates_to.event_id.as_str())
    //             .await
    //         {
    //             tokio::spawn(sas_verification_handler(client, sas));
    //         }
    //     },
    // );

    // // removed Sept 2024, following matrix-rust-sdk/examples/emoji_verification
    // client.add_event_handler(
    //     |ev: OriginalSyncKeyVerificationDoneEvent, client: Client| async move {
    //         debug!("OriginalSyncKeyVerificationDoneEvent");
    //         if let Some(Verification::SasV1(sas)) = client
    //             .encryption()
    //             .get_verification(&ev.sender, ev.content.relates_to.event_id.as_str())
    //             .await
    //         {
    //             if sas.is_done() {
    //                 print_success(&sas);
    //                 print_devices(&ev.sender, &client).await;
    //             }
    //         }
    //     },
    // );

    // go into event loop to sync and to execute verify protocol
    println!("Ready and waiting ...");
    println!("Go to other Matrix client like Element and initiate Emoji verification there.");
    println!("Best to have the other Matrix client ready and waiting before you start");
    println!("{}.", get_prog_without_ext());
    client.sync(SyncSettings::new()).await?;

    Ok(())
}

// ###############################################################################################

/// Go into the event loop and implement the emoji verification protocol.
/// We are initiating the verification witn device recipient_device.
/// This is the main function, the access point, to emoji verification.
/// Remember it is interactive and will remain in the event loop until user
/// leaves with Control-C.
pub async fn sync_request_verification(
    client: &Client,
    recipient_user: String,
    recipient_device: String,
) -> matrix_sdk::Result<()> {
    client.add_event_handler(
        |ev: ToDeviceKeyVerificationRequestEvent, client: Client| async move {
            debug!("ToDeviceKeyVerificationRequestEvent: entering");
            let request = client
                .encryption()
                .get_verification_request(&ev.sender, &ev.content.transaction_id)
                .await
                .expect("Error: Request object wasn't created");

            tokio::spawn(request_verification_handler(client, request));
            debug!("ToDeviceKeyVerificationRequestEvent: leaving");
        },
    );

    client.add_event_handler(
        |ev: OriginalSyncRoomMessageEvent, client: Client| async move {
            debug!("OriginalSyncRoomMessageEvent: entering");
            if let MessageType::VerificationRequest(_) = &ev.content.msgtype {
                let request = client
                    .encryption()
                    .get_verification_request(&ev.sender, &ev.event_id)
                    .await
                    .expect("Error: Request object wasn't created");

                tokio::spawn(request_verification_handler(client, request));
            }
            debug!("OriginalSyncRoomMessageEvent: leaving");
        },
    );

    client.add_event_handler(|_ev: SyncRoomMessageEvent, _client: Client| async move {
        debug!("SyncRoomMessageEvent");
    });

    // needed as of Sept 2024
    client.add_event_handler(
        |ev: ToDeviceKeyVerificationStartEvent, client: Client| async move {
            debug!("ToDeviceKeyVerificationStartEvent");
            if let Some(Verification::SasV1(sas)) = client
                .encryption()
                .get_verification(&ev.sender, ev.content.transaction_id.as_str())
                .await
            {
                debug!(
                    "ToDeviceKeyVerificationStartEvent: Verification state has Emoji verification."
                );
                tokio::spawn(sas_verification_handler(client, sas));
            }
        },
    );

    // removed Sept 2024, following matrix-rust-sdk/examples/emoji_verification
    client.add_event_handler(
        |_ev: ToDeviceKeyVerificationReadyEvent, _client: Client| async move {
            debug!("ToDeviceKeyVerificationReadyEvent");
        },
    );

    // removed Sept 2024, following matrix-rust-sdk/examples/emoji_verification
    client.add_event_handler(
        |_ev: ToDeviceKeyVerificationAcceptEvent, _client: Client| async move {
            debug!("ToDeviceKeyVerificationAcceptEvent");
        },
    );

    // removed Sept 2024, following matrix-rust-sdk/examples/emoji_verification
    client.add_event_handler(
        |_ev: ToDeviceKeyVerificationCancelEvent, _client: Client| async move {
            debug!("ToDeviceKeyVerificationCancelEvent");
        },
    );

    // removed Sept 2024, following matrix-rust-sdk/examples/emoji_verification
    client.add_event_handler(
        |_ev: ToDeviceKeyVerificationKeyEvent, _client: Client| async move {
            debug!("ToDeviceKeyVerificationKeyEvent");
            // if let Some(Verification::SasV1(sas)) = client
            //     .encryption()
            //     .get_verification(&ev.sender, ev.content.transaction_id.as_str())
            //     .await
            // {
            //     tokio::spawn(sas_verification_handler(client, sas));
            // }
        },
    );

    // removed Sept 2024, following matrix-rust-sdk/examples/emoji_verification
    client.add_event_handler(
        |_ev: ToDeviceKeyVerificationDoneEvent, _client: Client| async move {
            debug!("ToDeviceKeyVerificationDoneEvent");
            // if let Some(Verification::SasV1(sas)) = client
            //     .encryption()
            //     .get_verification(&ev.sender, ev.content.transaction_id.as_str())
            //     .await
            // {
            //     if sas.is_done() {
            //         print_success(&sas);
            //         print_devices(&ev.sender, &client).await;
            //     }
            // }
        },
    );

    // removed Sept 2024, following matrix-rust-sdk/examples/emoji_verification
    client.add_event_handler(
        |_ev: OriginalSyncKeyVerificationStartEvent, _client: Client| async move {
            debug!("OriginalSyncKeyVerificationStartEvent");
            // if let Some(Verification::SasV1(sas)) = client
            //     .encryption()
            //     .get_verification(&ev.sender, ev.content.relates_to.event_id.as_str())
            //     .await
            // {
            //     println!(
            //         "Starting verification with {} {}",
            //         &sas.other_device().user_id(),
            //         &sas.other_device().device_id()
            //     );
            //     print_devices(&ev.sender, &client).await;
            //     sas.accept().await.unwrap();
            // }
        },
    );

    // removed Sept 2024, following matrix-rust-sdk/examples/emoji_verification
    client.add_event_handler(
        |_ev: OriginalSyncKeyVerificationKeyEvent, _client: Client| async move {
            debug!("OriginalSyncKeyVerificationKeyEvent");
            // if let Some(Verification::SasV1(sas)) = client
            //     .encryption()
            //     .get_verification(&ev.sender, ev.content.relates_to.event_id.as_str())
            //     .await
            // {
            //     tokio::spawn(sas_verification_handler(client, sas));
            // }
        },
    );

    // removed Sept 2024, following matrix-rust-sdk/examples/emoji_verification
    client.add_event_handler(
        |_ev: OriginalSyncKeyVerificationDoneEvent, _client: Client| async move {
            debug!("OriginalSyncKeyVerificationDoneEvent");
            // if let Some(Verification::SasV1(sas)) = client
            //     .encryption()
            //     .get_verification(&ev.sender, ev.content.relates_to.event_id.as_str())
            //     .await
            // {
            //     if sas.is_done() {
            //         print_success(&sas);
            //         print_devices(&ev.sender, &client).await;
            //     }
            // }
        },
    );

    // go into event loop to sync and to execute verify protocol
    println!("Ready and waiting ...");
    println!("We send request to other Matrix client like Element and initiate Emoji ");
    println!("verification with them. Best to have the other Matrix client ready and ");
    println!("waiting before you start {}.", get_prog_without_ext());
    println!(
        "\n ### THIS IS PARTIALLY BROKEN. DOES NOT SEEM TO WORK WITH ELEMENT ANDROID APP. ###\
        \n ### BUT IT DOES WORK WITH ELEMENT WEB APP IN BROWSER. ###\n"
    );
    println!(
        "Sending request to user's {:?} device {:?}.",
        recipient_user, recipient_device
    );

    let encryption = client.encryption();
    let userid: OwnedUserId = UserId::parse(recipient_user).unwrap();
    let deviceid: OwnedDeviceId = OwnedDeviceId::from(recipient_device);
    match encryption.get_device(&userid, &deviceid).await {
        Ok(Some(device)) => {
            // -> Result<Option<Device>, CryptoStoreError>
            debug!(
                "Is device {} already verified? {:?}",
                device.device_id(),
                device.is_verified()
            );

            // if !device.is_verified() {
            // We don't want to support showing a QR code, we only support SAS
            // verification
            let methods = vec![VerificationMethod::SasV1];
            let verification = device.request_verification_with_methods(methods).await?;
            // let verification = device.request_verification().await?;
            debug!(
                "verification: we_started is {:?}",
                verification.we_started()
            );
            debug!(
                "verification with device {} was requested.",
                device.device_id()
            );
            // }
        }
        Ok(None) => error!("Error: device not found: {:?}", deviceid),
        Err(e) => error!("Error: could not get device: {:?}", e),
    }
    client.sync(SyncSettings::new()).await?;

    Ok(())
}
