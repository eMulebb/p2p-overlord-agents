use super::dump;
use super::{
    CT_EMULE_MISCOPTIONS1, CT_EMULE_MISCOPTIONS2, CT_EMULE_UDPPORTS, CT_EMULE_VERSION, CT_NAME,
    CT_VERSION, DownloadSessionOptions, DownloadWindowLimits, ED2K_EMBLOCK_SIZE,
    ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED, ED2K_SOURCE_EXCHANGE2_VERSION, EDONKEY_VERSION,
    EMULE_CRYPT_REQUESTS, EMULE_CRYPT_SUPPORTS, EMULE_ENCRYPTION_METHOD_OBFUSCATION,
    EMULE_INFO_FEATURES, EMULE_PROTOCOL_VERSION, EMULE_TCP_CRYPT_MAGIC_REQUESTER,
    EMULE_TCP_CRYPT_MAGIC_SERVER, EMULE_TCP_CRYPT_MAGIC_SYNC, EMULE_VERSION_SHORT, ET_COMMENTS,
    ET_FEATURES, Ed2kAichHashset, Ed2kConnectionContext, Ed2kFileIdentifier,
    Ed2kHashsetRequestOptions, Ed2kHelloIdentity, Ed2kPeerConnectMode, Ed2kPeerDownloadOptions,
    Ed2kPeerDownloadOutcome, Ed2kPeerSecureIdentState, Ed2kSecureIdent, Ed2kTransport,
    Ed2kTransportMode, EmuleTcpPacket, FirewallCheckUdpRequest, HELLO_NICKNAME, OP_ACCEPTUPLOADREQ,
    OP_AICHANSWER, OP_AICHFILEHASHANS, OP_AICHFILEHASHREQ, OP_AICHREQUEST, OP_ANSWERSOURCES,
    OP_ANSWERSOURCES2, OP_BUDDYPING, OP_BUDDYPONG, OP_CALLBACK, OP_CANCELTRANSFER,
    OP_CHANGE_CLIENT_ID, OP_COMPRESSEDPART, OP_EDONKEYPROT, OP_EMULEINFO, OP_EMULEINFOANSWER,
    OP_EMULEPROT, OP_END_OF_DOWNLOAD, OP_FILEDESC, OP_FILESTATUS, OP_FWCHECKUDPREQ,
    OP_HASHSETANSWER2, OP_HASHSETREQUEST2, OP_HELLO, OP_HELLOANSWER, OP_KAD_FWTCPCHECK_ACK,
    OP_MULTIPACKET_EXT, OP_MULTIPACKET_EXT2, OP_MULTIPACKETANSWER, OP_OUTOFPARTREQS, OP_PACKEDPROT,
    OP_PORTTEST, OP_PREVIEWANSWER, OP_PUBLICIP_ANSWER, OP_PUBLICIP_REQ, OP_PUBLICKEY,
    OP_QUEUERANKING, OP_REASKCALLBACKTCP, OP_REQFILENAMEANSWER, OP_REQUESTFILENAME,
    OP_REQUESTPARTS, OP_REQUESTPARTS_I64, OP_REQUESTPREVIEW, OP_REQUESTSOURCES, OP_REQUESTSOURCES2,
    OP_SECIDENTSTATE, OP_SENDINGPART, OP_SETREQFILEID, OP_SIGNATURE, OP_STARTUPLOADREQ,
    PeerSourceExchangeRequest, PendingCompressedPart, SourceExchangePeer, TAGTYPE_UINT32,
    begin_secure_ident_probe, build_hello_responses, build_upload_part_packets,
    connect_callback_peer, decode_aich_file_hash_answer, decode_aich_recovery_answer_payload,
    decode_aich_recovery_request_payload, decode_answer_sources_payload,
    decode_client_id_change_payload, decode_compressed_part_fragment,
    decode_file_description_payload, decode_hashset_answer2, decode_hashset_request2,
    decode_hello_profile, decode_incoming_obfuscation_header, decode_kad_callback_payload,
    decode_peer_payload, decode_preview_answer_payload, decode_preview_request_payload,
    decode_public_ip_answer_payload, decode_public_key_payload, decode_reask_callback_tcp_payload,
    decode_request_parts_payload, decode_secident_state, decode_sending_part_payload,
    derive_obfuscation_key, download_file_from_peer, drive_download_session, ed2k_string_tag_type,
    emule_connect_options, emule_misc_options1, emule_misc_options2, emule_version_tag,
    encode_accept_upload_req, encode_aich_file_hash_answer, encode_aich_file_hash_request,
    encode_aich_recovery_failure_answer, encode_answer_sources, encode_answer_sources2,
    encode_compressed_part_fragment, encode_emule_info_answer, encode_emule_info_request,
    encode_hashset_answer2, encode_hashset_request2, encode_hello_answer, encode_hello_request,
    encode_incoming_obfuscation_response, encode_multipacket_answer,
    encode_multipacket_ext2_request, encode_multipacket_request, encode_packed_packet,
    encode_packet, encode_port_test_answer, encode_public_ip_answer, encode_queue_ranking,
    encode_request_filename, encode_request_filename_answer, encode_request_parts_batch,
    encode_request_sources2, encode_secident_state, encode_sending_part, encode_start_upload_req,
    enrich_hello_identity, handle_connection, inflate_compressed_part_fragment, is_mule_hello,
    next_download_read_timeout, request_udp_firewall_check, select_download_window_limits,
};
use crate::{
    ed2k_server::{Ed2kFoundSource, Ed2kServerState},
    ed2k_transfer::{
        ED2K_PART_SIZE, Ed2kResumeManifest, Ed2kSourceHint, Ed2kTransferRuntime,
        Ed2kUploadQueueConfig, new_transfer_job,
    },
    kad_firewall::KadFirewallState,
    paths::unique_test_dir,
};
use flate2::Decompress;
use hex::decode;
use md4::{Digest, Md4};
use overlord_kad_dht::{DhtConfig, DhtNode};
use overlord_kad_proto::{Ed2kHash, NodeId};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1v15::{Signature, VerifyingKey},
    pkcs8::EncodePublicKey,
    rand_core::OsRng,
    signature::Verifier,
};
use sha1::Sha1;
use std::collections::VecDeque;
use std::io::{self, Write as _};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, RwLock},
};

macro_rules! download_file_from_peer_test {
    (
            $bind_ip:expr,
            $peer:expr,
            $hello_identity:expr,
            $secure_ident:expr,
            $transfer_runtime:expr,
            $canonical_name:expr,
            $file_size:expr,
            $timeout:expr $(,)?
        ) => {
        download_file_from_peer(Ed2kPeerDownloadOptions {
            bind_ip: $bind_ip,
            peer: $peer,
            hello_identity: $hello_identity,
            secure_ident: $secure_ident,
            transfer_runtime: $transfer_runtime,
            canonical_name: $canonical_name,
            file_size: $file_size,
            timeout: $timeout,
        })
    };
}

macro_rules! handle_connection_test {
    (
            $stream:expr,
            $peer_addr:expr,
            $dht:expr,
            $server_state:expr,
            $kad_firewall:expr,
            $secure_ident:expr,
            $transfer_runtime:expr,
            $hello_identity:expr $(,)?
        ) => {
        super::handle_connection(
            $stream,
            $peer_addr,
            super::Ed2kConnectionContext {
                dht: $dht,
                server_state: $server_state,
                kad_firewall: $kad_firewall,
                secure_ident: $secure_ident,
                transfer_runtime: $transfer_runtime,
                hello_identity: $hello_identity,
            },
        )
    };
}

fn assert_startup_multipacket_ext2(
    protocol: u8,
    opcode: u8,
    payload: &[u8],
    file_hash: &Ed2kHash,
    file_size: u64,
    expect_set_req_file_id: bool,
) {
    assert_startup_multipacket_ext2_with_source_exchange(
        protocol,
        opcode,
        payload,
        file_hash,
        file_size,
        expect_set_req_file_id,
        true,
    );
}

fn assert_startup_multipacket_ext2_with_source_exchange(
    protocol: u8,
    opcode: u8,
    payload: &[u8],
    file_hash: &Ed2kHash,
    file_size: u64,
    expect_set_req_file_id: bool,
    expect_request_sources2: bool,
) {
    assert_eq!(protocol, OP_EMULEPROT);
    assert_eq!(opcode, super::OP_MULTIPACKET_EXT2);
    let (identifier, mut remaining) = super::Ed2kFileIdentifier::decode(payload).unwrap();
    assert_eq!(identifier.file_hash, *file_hash);
    assert_eq!(
        identifier.file_size,
        Some(file_size).filter(|size| *size != 0)
    );

    let mut saw_request_filename = false;
    let mut saw_request_sources2 = false;
    let mut saw_set_req_file_id = false;
    while let Some((&sub_opcode, rest)) = remaining.split_first() {
        remaining = rest;
        match sub_opcode {
            super::OP_REQUESTFILENAME => {
                remaining = super::skip_request_filename_ext_info(remaining, file_size).unwrap();
                saw_request_filename = true;
            }
            super::OP_SETREQFILEID => {
                saw_set_req_file_id = true;
            }
            super::OP_REQUESTSOURCES2 => {
                assert!(remaining.len() >= 3, "short OP_REQUESTSOURCES2 sub-payload");
                assert_eq!(
                    &remaining[..3],
                    &super::encode_request_sources2_subpayload()
                );
                remaining = &remaining[3..];
                saw_request_sources2 = true;
            }
            unexpected => panic!("unexpected startup sub-op 0x{unexpected:02X}"),
        }
    }

    assert!(saw_request_filename);
    assert_eq!(saw_request_sources2, expect_request_sources2);
    assert_eq!(saw_set_req_file_id, expect_set_req_file_id);
}

fn encode_startup_multipacket_ext2_answer_with_identifier(
    file_identifier: &super::Ed2kFileIdentifier,
    file_name: &str,
    include_file_status: bool,
) -> Vec<u8> {
    super::encode_multipacket_ext2_answer(file_identifier, file_name, true, include_file_status)
        .unwrap()
}

fn encode_startup_multipacket_ext2_answer(
    file_hash: &Ed2kHash,
    file_size: u64,
    file_name: &str,
    include_file_status: bool,
) -> Vec<u8> {
    encode_startup_multipacket_ext2_answer_with_identifier(
        &super::Ed2kFileIdentifier {
            file_hash: *file_hash,
            file_size: Some(file_size).filter(|size| *size != 0),
            aich_root: None,
        },
        file_name,
        include_file_status,
    )
}

mod common;
mod download;
mod download_fixture;
mod listener;
mod listener_fixture;
mod protocol;

use common::*;
use download_fixture::*;
use listener_fixture::*;
