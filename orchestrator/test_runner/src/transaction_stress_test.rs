use crate::{happy_path::test_valset_update, utils::*, COSMOS_NODE_GRPC, TOTAL_TIMEOUT};
use actix::{
    clock::{delay_for, Instant},
    Arbiter,
};
use clarity::PrivateKey as EthPrivateKey;
use clarity::{Address as EthAddress, Uint256};
use contact::client::Contact;
use cosmos_peggy::send::send_request_batch;
use deep_space::address::Address as CosmosAddress;
use deep_space::coin::Coin;
use deep_space::private_key::PrivateKey as CosmosPrivateKey;
use ethereum_peggy::send_to_cosmos::send_to_cosmos;
use futures::future::join_all;
use orchestrator::main_loop::orchestrator_main_loop;
use peggy_proto::peggy::query_client::QueryClient as PeggyQueryClient;
use rand::Rng;
use std::time::Duration;
use tonic::transport::Channel;
use web30::client::Web3;

const TIMEOUT: Duration = Duration::from_secs(60);

pub fn one_eth() -> Uint256 {
    1_000_000_000_000_000_000u128.into()
}

pub struct BridgeUserKey {
    pub eth_address: EthAddress,
    pub eth_key: EthPrivateKey,
    pub cosmos_address: CosmosAddress,
    pub cosmos_key: CosmosPrivateKey,
}

/// Perform a stress test by sending thousands of
/// transactions and producing large batches
#[allow(clippy::too_many_arguments)]
pub async fn transaction_stress_test(
    web30: &Web3,
    grpc_client: PeggyQueryClient<Channel>,
    contact: &Contact,
    keys: Vec<(CosmosPrivateKey, EthPrivateKey)>,
    peggy_address: EthAddress,
    test_token_name: String,
    erc20_addresses: Vec<EthAddress>,
    fee: Coin,
) {
    let mut grpc_client = grpc_client;

    // start orchestrators
    for (c_key, e_key) in keys.iter() {
        info!("Spawning Orchestrator");
        let grpc_client = PeggyQueryClient::connect(COSMOS_NODE_GRPC).await.unwrap();
        // we have only one actual futures executor thread (see the actix runtime tag on our main function)
        // but that will execute all the orchestrators in our test in parallel
        Arbiter::spawn(orchestrator_main_loop(
            *c_key,
            *e_key,
            web30.clone(),
            contact.clone(),
            grpc_client,
            peggy_address,
            test_token_name.clone(),
        ));
    }
    // send one update so we don't get warnings about there being no valsets
    test_valset_update(&contact, &web30, &keys, peggy_address, fee.clone()).await;

    // Generate 100 user keys to send ETH and multiple types of tokens
    let mut user_keys = Vec::new();
    for _ in 0..1000 {
        let mut rng = rand::thread_rng();
        let secret: [u8; 32] = rng.gen();
        let cosmos_key = CosmosPrivateKey::from_secret(&secret);
        let cosmos_address = cosmos_key.to_public_key().unwrap().to_address();
        let eth_key = EthPrivateKey::from_slice(&secret).unwrap();
        let eth_address = eth_key.to_public_key().unwrap();
        user_keys.push(BridgeUserKey {
            eth_address,
            eth_key,
            cosmos_address,
            cosmos_key,
        })
    }
    info!("Generated {} user keys", user_keys.len());
    let eth_destinations: Vec<EthAddress> = user_keys.iter().map(|i| i.eth_address).collect();
    send_eth_bulk(
        1_000_000_000_000_000_000u128.into(),
        &eth_destinations,
        web30,
    )
    .await;
    info!("Sent 1 ETH to {} addresses", user_keys.len());
    for token in erc20_addresses.iter() {
        send_erc20_bulk(one_eth(), *token, &eth_destinations, web30).await;
        info!("Sent 1 {} to {} addresses", token, user_keys.len());
    }
    for token in erc20_addresses.iter() {
        let mut sends = Vec::new();
        for keys in user_keys.iter() {
            let fut = send_to_cosmos(
                *token,
                peggy_address,
                one_eth(),
                keys.cosmos_address,
                keys.eth_key,
                Some(TIMEOUT),
                web30,
                Vec::new(),
            );
            sends.push(fut);
        }
        // stop and send all these transactions, can't do this in the outer loop
        // without nonce issues
        let txids = join_all(sends).await;
        let mut wait_for_txid = Vec::new();
        for txid in txids {
            let wait = web30.wait_for_transaction(txid.unwrap(), TIMEOUT, None);
            wait_for_txid.push(wait);
        }
        join_all(wait_for_txid).await;
        info!("Locked 1 {} for {} addresses", token, user_keys.len());
    }

    // wait for the bridge
    let start = Instant::now();
    let mut good = true;
    while Instant::now() - start < TOTAL_TIMEOUT {
        good = true;
        for token in erc20_addresses.iter() {
            for keys in user_keys.iter() {
                let balances = contact
                    .get_balances(keys.cosmos_address)
                    .await
                    .unwrap()
                    .result;
                let intended = Coin {
                    denom: format!("peggy/{}", token),
                    amount: one_eth(),
                };
                if !balances.contains(&intended) {
                    trace!("User is missing {} on Cosmos", token);
                    good = false;
                }
                delay_for(Duration::from_millis(10)).await;
            }
        }
        if good {
            break;
        }
    }
    assert!(good);
    info!("Successfully bridged all the things!");

    // for token in erc20_addresses.iter() {
    //     let denom = format!("peggy/{}", token);
    //     send_request_batch(keys[0].0, denom, fee.clone(), contact)
    //         .await
    //         .unwrap();
    // }
    // batch and send back to Cosmos
}
