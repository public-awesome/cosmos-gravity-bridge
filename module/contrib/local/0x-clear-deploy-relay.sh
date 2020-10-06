#!/bin/bash
set -eu

script_dir="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
project_dir=$script_dir/../../..

echo "## Reset chain state"
pkill peggyd || true # allowed to fail
pkill npm || true # allowed to fail

echo "## Cleanup"
rm -f "$project_dir/evm.log"
rm -f "$project_dir/peggyd.log"
rm -rf ~/.peggyd/
"${script_dir}/setup_node.sh"

echo "## Start chains"
touch "$project_dir/evm.log"
touch "$project_dir/peggyd.log"

peggyd start --rpc.laddr tcp://0.0.0.0:26657 --trace --log_level="main:info,state:debug,*:error" >> "$project_dir"/peggyd.log&

pushd "$project_dir"/solidity
npm run typechain ; npm run evm >> "$project_dir/evm.log" &
npm test ./test/alex-demo-deploy.ts
popd

echo "### Initial account balance"
echo "==========================="
echo "## Query balance"
peggycli q account cosmos1fs348g3qgkzug50w7sv6c8yyarftuah20ud0pu || true

echo "### Start bootstrap process"
echo "==========================="
echo "## Observe bridge contract setup and first Deposit"
peggycli tx peggy unsafe_testing relay eth  0x8858eeB3DfffA017D4BCE9801D340D36Cf895CCf 0x7c2C195CD6D34B8F845992d380aADB2730bB9C6F 0x2c7dd57db9fda0ea1a1428dcaa4bec1ff7c3bd7d1a88504754e0134b77badf57 --from validator --chain-id=testing  -y -b block

echo "## Query new balance"
peggycli q account cosmos1fs348g3qgkzug50w7sv6c8yyarftuah20ud0pu || true

echo "## Add ETH key"
peggycli tx peggy update-eth-addr 0xb8662f35f9de8720424e82b232e8c98d15399490adae9ca993f5ef1dc4883690 --from validator  --chain-id=testing -b block -y

echo "### Start multisig set update"
echo "============================="
echo "## Request valset update"
peggycli tx peggy valset-request --from validator --chain-id=testing -b block -y

echo "## Query pending request nonce"
nonce=$(peggycli q peggy pending-valset-request $(peggycli keys show validator -a) -o json | jq -r ".value.nonce")

echo "## Approve pending request"
peggycli tx peggy approved valset-confirm  "$nonce" 0xb8662f35f9de8720424e82b232e8c98d15399490adae9ca993f5ef1dc4883690 --from validator --chain-id=testing -b block -y

echo "## View attestations"
peggycli q peggy attestation orchestrator_signed_multisig_update $nonce -o json | jq

echo "## Submit multisig update"
peggycli tx peggy unsafe_testing relay cosmos  0x8858eeB3DfffA017D4BCE9801D340D36Cf895CCf 0x7c2C195CD6D34B8F845992d380aADB2730bB9C6F 0x2c7dd57db9fda0ea1a1428dcaa4bec1ff7c3bd7d1a88504754e0134b77badf57 --from validator --chain-id=testing  -y -b block

echo "## Observe multisig update"
peggycli tx peggy unsafe_testing relay eth  0x8858eeB3DfffA017D4BCE9801D340D36Cf895CCf 0x7c2C195CD6D34B8F845992d380aADB2730bB9C6F 0x2c7dd57db9fda0ea1a1428dcaa4bec1ff7c3bd7d1a88504754e0134b77badf57 --from validator --chain-id=testing  -y -b block

echo "### Start withdraw process"
echo "=========================="
echo "## Query balance"
peggycli q account cosmos1fs348g3qgkzug50w7sv6c8yyarftuah20ud0pu

echo "## Add ETH withdraw to pool"
peggycli tx peggy withdraw alice 0xc783df8a850f42e7f7e57013759c285caa701eb6 1peggy39b512461b 0peggy39b512461b --from alice --chain-id=testing -b block -y

echo "## Request a batch for outgoing TX"
peggycli tx peggy build-batch peggy39b512461b --from alice --chain-id=testing -b block -y

echo "## Query pending request nonce"
nonce=$(peggycli q peggy pending-batch-request $(peggycli keys show validator -a) -o json | jq -r ".value.nonce")

echo "## Approve pending request"
peggycli tx peggy approved batch-confirm  "$nonce" 0xb8662f35f9de8720424e82b232e8c98d15399490adae9ca993f5ef1dc4883690 --from validator --chain-id=testing -b block -y

echo "## Submit batch to Ethereum"
peggycli tx peggy unsafe_testing relay cosmos  0x8858eeB3DfffA017D4BCE9801D340D36Cf895CCf 0x7c2C195CD6D34B8F845992d380aADB2730bB9C6F 0x2c7dd57db9fda0ea1a1428dcaa4bec1ff7c3bd7d1a88504754e0134b77badf57 --from validator --chain-id=testing  -y -b block

echo "## Observe batch execution"
peggycli tx peggy unsafe_testing relay eth  0x8858eeB3DfffA017D4BCE9801D340D36Cf895CCf 0x7c2C195CD6D34B8F845992d380aADB2730bB9C6F 0x2c7dd57db9fda0ea1a1428dcaa4bec1ff7c3bd7d1a88504754e0134b77badf57 --from validator --chain-id=testing  -y -b block

echo "## View attestations"
peggycli q peggy attestation bridge_withdrawal_batch "$nonce" -o json | jq

echo "## Query balance"
peggycli q account cosmos1fs348g3qgkzug50w7sv6c8yyarftuah20ud0pu

echo "## Query last observed state"
peggycli q peggy observed nonces -o json