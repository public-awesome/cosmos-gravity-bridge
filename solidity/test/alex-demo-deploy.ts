import chai from "chai";
import {ethers} from "@nomiclabs/buidler";
import {solidity} from "ethereum-waffle";

import {deployContracts, loadContracts} from "../test-utils";
import {examplePowers} from "../test-utils/pure";

chai.use(solidity);
const {expect} = chai;

describe("Alex demo", function () {
    it("Transfer out to cosmos", async function () {
        const signers = await ethers.getSigners();
        const peggyId = ethers.utils.formatBytes32String("foo");

        // This is the power distribution on the Cosmos hub as of 7/14/2020
        let powers = [100];
        let validators = ["0xb462864E395d88d6bc7C5dd5F3F5eb4cc2599255"]

        const powerThreshold = 66;

        const {
            peggy,
            testERC20,
            checkpoint: deployCheckpoint
        } = await deployContracts(peggyId, validators, powers, powerThreshold);

        // const {
        //     peggy,
        //     testERC20,
        // } = await loadContracts();
        console.log("peggy: " + peggy.address)
        console.log("erc20: " + testERC20.address)
        console.log("checkpoint: " + deployCheckpoint)

        expect(await peggy.functions.state_peggyId()).to.equal(peggyId);
        expect(await peggy.functions.state_tokenContract()).to.equal(
            testERC20.address
        );

        // Transferring out to Cosmos

        let amount = 20;
        await testERC20.functions.approve(peggy.address, amount);

        await peggy.functions.transferOut(
            "cosmos1fs348g3qgkzug50w7sv6c8yyarftuah20ud0pu",
            amount
        );

        // const numTxs = 1;
        // const txDestinationsInt = new Array(numTxs);
        // const txFees = new Array(numTxs);
        // const txNonces = new Array(numTxs);
        // const txAmounts = new Array(numTxs);
        // for (let i = 0; i < numTxs; i++) {
        //     txNonces[i] = i + 1;
        //     txFees[i] = 1;
        //     txAmounts[i] = 1;
        //     txDestinationsInt[i] = signers[i + 5];
        // }
        // console.log(5)


        //
        // // Transferring into ERC20 from Cosmos
        // const txDestinations = await getSignerAddresses(txDestinationsInt);
        //
        // let txHash = makeTxBatchHash(
        //   txAmounts,
        //   txDestinations,
        //   txFees,
        //   txNonces,
        //   peggyId
        // );
        //
        // sigs = await signHash(newValidators, txHash);
        //
        // await peggy.submitBatch(
        //   await getSignerAddresses(newValidators),
        //   newPowers,
        //   newValsetNonce,
        //   sigs.v,
        //   sigs.r,
        //   sigs.s,
        //   txAmounts,
        //   txDestinations,
        //   txFees,
        //   txNonces
        // );

        //     expect(
        //         await (
        //             await testERC20.functions.balanceOf(await signers[6].getAddress())
        //         ).toNumber()
        //     ).to.equal(amount);
    });
});
