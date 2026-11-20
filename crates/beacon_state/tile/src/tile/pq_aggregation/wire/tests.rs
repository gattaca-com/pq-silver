use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
};

use super::*;

fn claim(tag: u8) -> Claim {
    [tag; 64]
}

fn le(value: usize) -> [u8; 8] {
    (value as u64).to_le_bytes()
}

/// The protocol's `aggregate` layout, appended field by field.
fn naive_body(request: &AggregateRequest) -> Vec<u8> {
    let mut body = vec![OP_AGGREGATE, request.log_inv_rate];
    body.extend(le(request.children.len()));
    for (claims, proof) in &request.children {
        body.extend(le(8 + claims.len() * 64 + 8 + 1));
        body.extend(le(claims.len()));
        claims.iter().for_each(|claim| body.extend(claim));
        body.extend(le(0));
        body.push(0);
        body.extend(le(proof.len()));
        body.extend(*proof);
    }
    body.extend(le(request.records.len()));
    for (claim, signature) in &request.records {
        body.extend(*claim);
        body.extend(*signature);
    }
    body.extend([0; 8 + 8 + 1]);
    body
}

#[test]
fn an_aggregate_request_has_the_protocol_layout() {
    let signature = [9u8; XMSS_SIGNATURE_SIZE];
    let records = [(claim(1), signature), (claim(2), signature)];
    let child = [claim(3)];
    let request = AggregateRequest {
        log_inv_rate: 2,
        children: vec![(&child, b"pp")],
        records: records.iter().map(|(claim, signature)| (claim, signature)).collect(),
    };
    let mut out = vec![0xAA; request.len()];
    request.write(&mut out);

    let mut expected = vec![1, 2];
    expected.extend(le(1));
    expected.extend(le(8 + 64 + 8 + 1));
    expected.extend(le(1));
    expected.extend(claim(3));
    expected.extend(le(0));
    expected.push(0);
    expected.extend(le(2));
    expected.extend(b"pp");
    expected.extend(le(2));
    for (claim, signature) in &records {
        expected.extend(claim);
        expected.extend(signature);
    }
    expected.extend([0; 8 + 8 + 1]);
    assert_eq!(out, expected);
}

#[test]
fn the_length_is_exactly_the_bytes_written() {
    let signature = [5u8; XMSS_SIGNATURE_SIZE];
    let claims: Vec<Claim> = (0..=255).map(claim).collect();
    let records: Vec<_> = (0..2048).map(|i| (&claims[i % 256], &signature)).collect();
    let proof = vec![3u8; 1000];
    let best = (&claims[..100], &proof[..]);
    let sixteen: Vec<_> = (0..16).map(|i| (&claims[i..i + 1], &proof[..i])).collect();
    let shapes = [
        (vec![], vec![]),
        (vec![best], vec![]),
        (sixteen, vec![]),
        (vec![best], records.clone()),
        (vec![], records[..3].to_vec()),
    ];
    for (children, records) in shapes {
        let request = AggregateRequest { log_inv_rate: 2, children, records };
        let mut out = vec![0xAA; request.len()];
        request.write(&mut out);
        assert_eq!(out, naive_body(&request));
    }
}

#[test]
#[should_panic(expected = "shorter than its slice")]
fn a_slice_longer_than_the_request_is_a_bug() {
    let request = AggregateRequest { log_inv_rate: 2, children: vec![], records: vec![] };
    request.write(&mut vec![0; request.len() + 1]);
}

#[test]
fn a_good_response_decodes() {
    let body = aggregate_response(&[claim(1), claim(2)], b"proof");
    let (claims, proof) = decode_aggregate_response(&body).unwrap();
    assert_eq!(claims, [claim(1), claim(2)]);
    assert_eq!(proof, b"proof");
}

#[test]
fn every_malformed_response_is_refused() {
    let good = aggregate_response(&[claim(1), claim(2)], b"proof");
    assert!(decode_aggregate_response(&[]).is_err());
    assert!(decode_aggregate_response(&good[..good.len() - 1]).is_err(), "truncated");
    assert!(decode_aggregate_response(&[good.clone(), vec![0]].concat()).is_err(), "trailing");
    assert!(
        decode_aggregate_response(&aggregate_response(&[claim(2), claim(1)], b"p")).is_err(),
        "unsorted"
    );
    assert!(
        decode_aggregate_response(&aggregate_response(&[claim(1), claim(1)], b"p")).is_err(),
        "repeated"
    );
    let big = vec![0; MAX_STARK_PROOF_SIZE + 1];
    assert!(
        decode_aggregate_response(&aggregate_response(&[claim(1)], &big)).is_err(),
        "proof too large"
    );

    let mut sphincs = good.clone();
    sphincs[1 + 8 + 8 + 128] = 1;
    assert!(decode_aggregate_response(&sphincs).is_err(), "leanSPHINCS claims");
    let mut da = good.clone();
    da[1 + 8 + 8 + 128 + 8] = 1;
    assert!(decode_aggregate_response(&da).is_err(), "DA commitment");

    let mut huge_count = good.clone();
    huge_count[9..17].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(decode_aggregate_response(&huge_count).is_err(), "count beyond the bytes present");
}

#[test]
fn a_rejection_is_an_error() {
    let mut body = vec![1];
    body.extend(le(3));
    body.extend(b"bad");
    assert_eq!(decode_aggregate_response(&body), Err("rejected by the leanvm sidecar"));
}

fn exchange(stream: &mut UnixStream, request: &[u8]) -> Vec<u8> {
    stream.write_all(&(request.len() as u64).to_le_bytes()).unwrap();
    stream.write_all(request).unwrap();
    read_frame(stream)
}

fn read_frame(stream: &mut UnixStream) -> Vec<u8> {
    let mut header = [0u8; 8];
    stream.read_exact(&mut header).unwrap();
    let mut body = vec![0; u64::from_le_bytes(header) as usize];
    stream.read_exact(&mut body).unwrap();
    body
}

/// `LEANVM_SIGNATURES` holds `pubkey | message | signature` records, as
/// leanVM's `bins/leanvm-sidecar/testdata/signatures-24000.bin`.
#[test]
#[ignore = "needs a leanvm-sidecar: set LEANVM_SIDECAR_SOCKET and LEANVM_SIGNATURES"]
fn a_real_sidecar_aggregates_then_extends() {
    const RECORD: usize = 64 + XMSS_SIGNATURE_SIZE;
    let mut bytes = vec![0; 16 * RECORD];
    let file = std::env::var("LEANVM_SIGNATURES").expect("LEANVM_SIGNATURES");
    std::fs::File::open(file).unwrap().read_exact(&mut bytes).unwrap();
    let records: Vec<(Claim, &[u8; XMSS_SIGNATURE_SIZE])> = bytes
        .chunks_exact(RECORD)
        .map(|record| (record[..64].try_into().unwrap(), record[64..].try_into().unwrap()))
        .collect();
    let sorted = |records: &[(Claim, &[u8; XMSS_SIGNATURE_SIZE])]| {
        let mut claims: Vec<Claim> = records.iter().map(|(claim, _)| *claim).collect();
        claims.sort_unstable();
        claims
    };

    let socket = std::env::var("LEANVM_SIDECAR_SOCKET").expect("LEANVM_SIDECAR_SOCKET");
    let mut stream = UnixStream::connect(socket).unwrap();
    assert!(read_frame(&mut stream).starts_with(b"leanvmsc"));

    let request = |children: Vec<_>, records: &[(Claim, &[u8; XMSS_SIGNATURE_SIZE])]| {
        let records = records.iter().map(|(claim, signature)| (claim, *signature)).collect();
        AggregateRequest { log_inv_rate: 2, children, records }.body()
    };
    let response = exchange(&mut stream, &request(vec![], &records[..8]));
    let (claims, proof) = decode_aggregate_response(&response).unwrap();
    assert_eq!(claims, sorted(&records[..8]));

    let child = (claims.as_slice(), proof);
    let response = exchange(&mut stream, &request(vec![child], &records[8..]));
    let (union, _) = decode_aggregate_response(&response).unwrap();
    assert_eq!(union, sorted(&records));
}
