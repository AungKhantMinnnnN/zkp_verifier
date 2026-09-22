use std::time::Duration;
use tokio::sync::watch;
use zkp_verifier::protocol::AuthRequest;
use zkp_verifier::tcp::{BankServer, UserProverClient};
use zkp_verifier::zkp_core_engine::{UserSecretKey, ZkpEngine};

#[tokio::test]
async fn test_tcp_happy_path_verification() {
    let server = BankServer::bind("127.0.0.1:0").await.expect("Failed to bind server");
    let addr = server.local_addr();

    let alice_sk = UserSecretKey::generate();
    let alice_pk = alice_sk.public_key();
    server.registry().register("alice_fintech", &alice_pk).expect("Failed to register user");

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_handle = tokio::spawn(async move {
        server.run(shutdown_rx).await.unwrap();
    });

    let mut client = UserProverClient::connect(&addr.to_string())
        .await
        .expect("Client failed to connect");

    let response = client
        .authenticate("alice_fintech", &alice_sk, false)
        .await
        .expect("Authentication request failed");

    assert!(response.success, "Valid proof must verify successfully");
    assert_eq!(response.user_id, "alice_fintech");
    assert!(response.message.contains("verified successfully"));

    shutdown_tx.send(true).unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    server_handle.abort();
}

#[tokio::test]
async fn test_tcp_unregistered_user_rejected() {
    let server = BankServer::bind("127.0.0.1:0").await.expect("Failed to bind server");
    let addr = server.local_addr();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_handle = tokio::spawn(async move {
        server.run(shutdown_rx).await.unwrap();
    });

    let mut client = UserProverClient::connect(&addr.to_string())
        .await
        .expect("Client failed to connect");

    let hacker_sk = UserSecretKey::generate();
    let response = client
        .authenticate("unknown_intruder", &hacker_sk, false)
        .await
        .expect("Authentication call failed");

    assert!(!response.success, "Unregistered user must be rejected");
    assert!(response.message.contains("not registered with bank"));

    shutdown_tx.send(true).unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    server_handle.abort();
}

#[tokio::test]
async fn test_tcp_replay_attack_rejected() {
    let server = BankServer::bind("127.0.0.1:0").await.expect("Failed to bind server");
    let addr = server.local_addr();

    let alice_sk = UserSecretKey::generate();
    let alice_pk = alice_sk.public_key();
    server.registry().register("alice_replay", &alice_pk).unwrap();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_handle = tokio::spawn(async move {
        server.run(shutdown_rx).await.unwrap();
    });

    let mut client = UserProverClient::connect(&addr.to_string())
        .await
        .expect("Client failed to connect");

    let proof = ZkpEngine::generate_proof(&alice_sk, &alice_pk);
    let request = AuthRequest {
        user_id: "alice_replay".to_string(),
        public_key: alice_pk.to_bytes(),
        proof,
    };

    // First attempt: Valid
    let response1 = client.send_raw_request(request.clone()).await.unwrap();
    assert!(response1.success, "First submission must be accepted");

    // Second attempt: Same proof replayed! Must be blocked
    let response2 = client.send_raw_request(request).await.unwrap();
    assert!(!response2.success, "Replayed proof must be rejected");
    assert!(response2.message.contains("Replay attack detected"));

    shutdown_tx.send(true).unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    server_handle.abort();
}

#[tokio::test]
async fn test_tcp_malicious_tampered_proof_rejected() {
    let server = BankServer::bind("127.0.0.1:0").await.expect("Failed to bind server");
    let addr = server.local_addr();

    let bob_sk = UserSecretKey::generate();
    let bob_pk = bob_sk.public_key();
    server.registry().register("bob_attacker", &bob_pk).unwrap();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_handle = tokio::spawn(async move {
        server.run(shutdown_rx).await.unwrap();
    });

    let mut client = UserProverClient::connect(&addr.to_string())
        .await
        .expect("Client failed to connect");

    let response = client
        .authenticate("bob_attacker", &bob_sk, true) // tamper = true
        .await
        .expect("Authentication request returned error");

    assert!(!response.success, "Tampered proof must be rejected by the bank verifier");
    assert_eq!(response.user_id, "bob_attacker");
    assert!(response.message.contains("Verification failed"));

    shutdown_tx.send(true).unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    server_handle.abort();
}

#[tokio::test]
async fn test_tcp_multiple_concurrent_clients() {
    let server = BankServer::bind("127.0.0.1:0").await.expect("Failed to bind server");
    let addr = server.local_addr();

    let mut sk_list = Vec::new();
    for i in 0..5 {
        let sk = UserSecretKey::generate();
        let user_name = format!("concurrent_user_{i}");
        server.registry().register(&user_name, &sk.public_key()).unwrap();
        sk_list.push((user_name, sk));
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_handle = tokio::spawn(async move {
        server.run(shutdown_rx).await.unwrap();
    });

    let mut handles = Vec::new();

    for (user_name, sk) in sk_list {
        let addr_str = addr.to_string();
        handles.push(tokio::spawn(async move {
            let mut client = UserProverClient::connect(&addr_str).await.unwrap();
            let resp = client.authenticate(&user_name, &sk, false).await.unwrap();
            assert!(resp.success);
            assert_eq!(resp.user_id, user_name);
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    shutdown_tx.send(true).unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    server_handle.abort();
}
