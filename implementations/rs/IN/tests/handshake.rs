#![allow(non_snake_case, non_upper_case_globals, unused_assignments, unused_imports)]

use noiseexplorer_in::{
	consts::{DHLEN, MAC_LENGTH},
	error::NoiseError,
	noisesession::NoiseSession,
	types::{Keypair, PrivateKey, PublicKey},
};

fn decode_str(s: &str) -> Vec<u8> {
 	hex::decode(s).unwrap()
 }

#[test]
fn noiseexplorer_test_in() {

	let mut prologue: Vec<u8> = Vec::new();
	let mut messageA: Vec<u8> = Vec::new();	
	let mut messageB: Vec<u8> = Vec::new();
	let mut messageC: Vec<u8> = Vec::new();
	let mut messageD: Vec<u8> = Vec::new();	
	let mut messageE: Vec<u8> = Vec::new();
	let mut messageF: Vec<u8> = Vec::new();

	prologue = decode_str("4a6f686e2047616c74");
	let initiator_static_private = PrivateKey::from_str("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1").unwrap();
	let responder_static_private = PrivateKey::from_str("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
	let initiator_static_kp = Keypair::from_private_key(initiator_static_private).unwrap();
	let responder_static_kp = Keypair::from_private_key(responder_static_private).unwrap();
	
	let mut initiator_session: NoiseSession = NoiseSession::init_session(true, &prologue[..], initiator_static_kp);
	let mut responder_session: NoiseSession = NoiseSession::init_session(false, &prologue[..], responder_static_kp);
	let initiator_ephemeral_private = PrivateKey::from_str("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a").unwrap();
	let initiator_ephemeral_kp = Keypair::from_private_key(initiator_ephemeral_private).unwrap();
	initiator_session.set_ephemeral_keypair(initiator_ephemeral_kp);
	let responder_ephemeral_private = PrivateKey::from_str("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b").unwrap();
	let responder_ephemeral_kp = Keypair::from_private_key(responder_ephemeral_private).unwrap();
	responder_session.set_ephemeral_keypair(responder_ephemeral_kp);
	messageA.extend_from_slice(&[0u8; DHLEN][..]);
	messageA.extend_from_slice(&[0u8; DHLEN][..]);
	messageA.extend_from_slice(&decode_str("4c756477696720766f6e204d69736573")[..]);
	let tA: Vec<u8> = Vec::from(&decode_str("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79446bc3822a2aa7f4e6981d6538692b3cdf3e6df9eea6ed269eb41d93c22757b75a4c756477696720766f6e204d69736573")[..]);
	// messageA length is 64 + payload length,
	// payload starts at index 64
	initiator_session.send_message(&mut messageA[..]).unwrap();
	responder_session.recv_message(&mut messageA.clone()[..]).unwrap();
	messageB.extend_from_slice(&[0u8; DHLEN][..]);
	messageB.extend_from_slice(&decode_str("4d757272617920526f746862617264")[..]);
	messageB.extend_from_slice(&[0u8; MAC_LENGTH][..]);
	let tB: Vec<u8> = Vec::from(&decode_str("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088432830411f43b780306e3f94b9e3becb18016c41fd51fa7ed38f1a6217bdee11")[..]);
	// messageB length is 48 + payload length,
	// payload starts at index 32
	responder_session.send_message(&mut messageB[..]).unwrap();
	initiator_session.recv_message(&mut messageB.clone()[..]).unwrap();
	messageC.extend_from_slice(&decode_str("462e20412e20486179656b")[..]);
	messageC.extend_from_slice(&[0u8; MAC_LENGTH][..]);
	let tC: Vec<u8> = Vec::from(&decode_str("822184f6ad708b7539c99ed858caf5ba56f2c57ba55d34dd3b6778")[..]);
	// messageC length is 16 + payload length,
	// payload starts at index 0
	initiator_session.send_message(&mut messageC[..]).unwrap();
	responder_session.recv_message(&mut messageC.clone()[..]).unwrap();
	messageD.extend_from_slice(&decode_str("4361726c204d656e676572")[..]);
	messageD.extend_from_slice(&[0u8; MAC_LENGTH][..]);
	let tD: Vec<u8> = Vec::from(&decode_str("2f97e72757dd3b46921ce96827cca0d01e819cfc7db9aaa85019b5")[..]);
	// messageD length is 16 + payload length,
	// payload starts at index 0
	responder_session.send_message(&mut messageD[..]).unwrap();
	initiator_session.recv_message(&mut messageD.clone()[..]).unwrap();
	messageE.extend_from_slice(&decode_str("4a65616e2d426170746973746520536179")[..]);
	messageE.extend_from_slice(&[0u8; MAC_LENGTH][..]);
	let tE: Vec<u8> = Vec::from(&decode_str("bea8ecf42785759819282424c5547c1f98b871a67d1d6e3fdcfb6c2c65d54f2ea1")[..]);
	// messageE length is 16 + payload length,
	// payload starts at index 0
	initiator_session.send_message(&mut messageE[..]).unwrap();
	responder_session.recv_message(&mut messageE.clone()[..]).unwrap();
	messageF.extend_from_slice(&decode_str("457567656e2042f6686d20766f6e2042617765726b")[..]);
	messageF.extend_from_slice(&[0u8; MAC_LENGTH][..]);
	let tF: Vec<u8> = Vec::from(&decode_str("3c9d968a1c6036ef29ef6a031678c621d1629cb96e25d8f11dfaa29e1591c5648e22089217")[..]);
	// messageF length is 16 + payload length,
	// payload starts at index 0
	responder_session.send_message(&mut messageF[..]).unwrap();
	initiator_session.recv_message(&mut messageF.clone()[..]).unwrap();
	assert!(tA == messageA, "\n\n\nTest A: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tA, messageA);
	assert!(tB == messageB, "\n\n\nTest B: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tB, messageB);
	assert!(tC == messageC, "\n\n\nTest C: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tC, messageC);
	assert!(tD == messageD, "\n\n\nTest D: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tD, messageD);
	assert!(tE == messageE, "\n\n\nTest E: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tE, messageE);
	assert!(tF == messageF, "\n\n\nTest F: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tF, messageF);
}
