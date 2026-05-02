use super::*;

#[tokio::test]
async fn listener_upload_peer_can_resume_partial_download_after_reconnect() {
    let payload = (0..32_768u32)
        .flat_map(|value| value.to_le_bytes())
        .collect::<Vec<_>>();
    let mut runtime = ListenerTestRuntime::new(
        "ed2k-upload-listener-resume-reconnect",
        listener_test_identity(0xA1, 0x5151_0101, 41002, 41003),
        [0x6E; 16],
        0x99AA_5500,
    )
    .await;
    let file = runtime
        .seed_verified_upload_file("resume.bin", payload)
        .await;
    let server = runtime.spawn_listener_loop();

    let peer_identity = listener_test_identity(0xB1, 0x7777_0001, 4662, 4666);
    let first_end = (file.payload.len() as u64) / 2;
    let second_start = first_end;
    let second_end = file.payload.len() as u64;

    let mut first_stream =
        connect_peer_until_upload_accepted(runtime.peer_addr, peer_identity, &file.file_hash).await;
    request_upload_parts(&mut first_stream, &file.file_hash, &[(0, first_end)]).await;
    let first_bytes = read_upload_bytes(&mut first_stream, &file.file_hash, 0, first_end).await;
    assert_eq!(
        first_bytes,
        file.payload[0..usize::try_from(first_end).unwrap()].to_vec()
    );
    drop(first_stream);

    let mut resumed_stream =
        connect_peer_until_upload_accepted(runtime.peer_addr, peer_identity, &file.file_hash).await;
    request_upload_parts(
        &mut resumed_stream,
        &file.file_hash,
        &[(second_start, second_end)],
    )
    .await;
    let resumed_bytes = read_upload_bytes(
        &mut resumed_stream,
        &file.file_hash,
        second_start,
        second_end,
    )
    .await;
    assert_eq!(
        resumed_bytes,
        file.payload[usize::try_from(second_start).unwrap()..usize::try_from(second_end).unwrap()]
            .to_vec()
    );

    send_cancel_transfer(&mut resumed_stream).await;
    drop(resumed_stream);
    server.abort();
}
