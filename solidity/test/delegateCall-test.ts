import chai from "chai";
import { ethers } from "@nomiclabs/buidler";
import { solidity } from "ethereum-waffle";
import { StorageTest } from "../typechain/StorageTest";
import { Caller } from "../typechain/Caller";
import { Callee } from "../typechain/Callee";
import { TestERC20A } from "../typechain/TestERC20A";
import { BigNumberish } from "ethers/utils";

import { deployContracts } from "../test-utils";
import { getSignerAddresses } from "../test-utils/pure";

chai.use(solidity);
const { expect } = chai;

describe.only("delegateCall test", function() {
  it("delegateCall test", async function() {
    const signers = await ethers.getSigners();
    const signerAddresses = await getSignerAddresses(signers)

    const Caller = await ethers.getContractFactory("Caller");
    const caller = (await Caller.deploy()) as Caller;
    await caller.deployed();

    const Callee = await ethers.getContractFactory("Callee");
    const callee = (await Callee.deploy()) as Callee;
    await callee.deployed();
  
    const TestERC20A = await ethers.getContractFactory("TestERC20A");
    const token = (await TestERC20A.deploy()) as TestERC20A;
    await token.deployed()

    await token.transfer(caller.address, 2)

    await caller.callOut(callee.address, token.address, signerAddresses[1])

    expect(await (await token.balanceOf(caller.address)).toNumber()).to.equal(1);
    expect(await (await token.balanceOf(signerAddresses[1])).toNumber()).to.equal(10001);
  })
});
