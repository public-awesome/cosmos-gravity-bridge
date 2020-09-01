#!/bin/bash
set -eux
# your gaiad binary name
BIN=peggyd
CLI=peggycli

NODES=$1

for i in $(seq 1 $NODES);
do
# add this ip for loopback dialing
ip addr add 7.7.7.$i/32 dev eth0 || true # allowed to fail

GAIA_HOME="--home /validator$i"
# this implicitly caps us at ~6000 nodes for this sim
# note that we start on 26656 the idea here is that the first
# node (node 1) is at the expected contact address from the gentx
# faciliating automated peer exchange
# not sure what this one does but we need to set it or we'll
# see port conflicts
LISTEN_ADDRESS="--address tcp://7.7.7.$i:26655"
RPC_ADDRESS="--rpc.laddr tcp://7.7.7.$i:26657"
P2P_ADDRESS="--p2p.laddr tcp://7.7.7.$i:26656"
LOG_LEVEL="--log_level *:error"
ARGS="$GAIA_HOME $LISTEN_ADDRESS $RPC_ADDRESS $P2P_ADDRESS $LOG_LEVEL"
$BIN $ARGS start &
done

# start the peggycli REST server this runs on port 1317 against localhost.
# it will be passed outside of the container for easy debugging/development
peggycli rest-server --laddr tcp://0.0.0.0:1317 --trust-node --node tcp://7.7.7.1:26657 &

# let the cosmos chain settle before starting eth as it
# consumes a lot of processing power
sleep 10

bash /peggy/tests/container-scripts/run-eth.sh &
sleep 10

# deploy peggy and our test ERC20 contract 'BitcoinMAX'
# note the eth private key passed here gets funds over in test/assets/ETHGenesis.json
# note the directory change to gain access to node_modules already installed for the solidity
# toolchain
pushd /peggy/solidity/
npx ts-node /peggy/solidity/contract-deployer.ts \
--eth-node=http://localhost:8545 \
--eth-privkey=0xb1bab011e03a9862664706fc3bbaa1b16651528e5f0e7fbfcbfdd8be302a13e7 \
--contract=/peggy/solidity/artifacts/Peggy.json \
--test-mode=true \
--erc20-contract=/peggy/solidity/artifacts/TestERC20.json

