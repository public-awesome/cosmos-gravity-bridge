import chai from "chai";
import { ethers } from "@nomiclabs/buidler";
import { solidity } from "ethereum-waffle";
import { StorageTest } from "../typechain/StorageTest";
import { BigNumberish } from "ethers/utils";

import { deployContracts } from "../test-utils";
import { getSignerAddresses } from "../test-utils/pure";

chai.use(solidity);
const { expect } = chai;

describe("Storage test", function() {
  it("Storage test", async function() {
    const StorageTest = await ethers.getContractFactory("StorageTest");

    const storageContract = (await StorageTest.deploy()) as StorageTest;

    await storageContract.deployed();

    await storageContract.storeKeyToBool(ethers.utils.formatBytes32String("foo"))
    await storageContract.storeKeyToUint(ethers.utils.formatBytes32String("foo"), 3)
  })
  // it("Storage test", async function() {
  //   const signers = await ethers.getSigners();
  //   const peggyId = ethers.utils.formatBytes32String("foo");

  //   let validators = [];
  //   let powers = [];

  //   for (let i = 0; i < 100; i++) {
  //     validators.push(signers[i]);
  //     powers.push(5000);
  //   }

  //   const HashingTest = await ethers.getContractFactory("HashingTest");

  //   const hashingContract = (await HashingTest.deploy()) as HashingTest;

  //   await hashingContract.deployed();

  //   await hashingContract.IterativeHash(
  //     await getSignerAddresses(validators),
  //     powers,
  //     1,
  //     peggyId
  //   );

  //   await hashingContract.ConcatHash(
  //     await getSignerAddresses(validators),
  //     powers,
  //     1,
  //     peggyId
  //   );

  //   await hashingContract.ConcatHash2(
  //     await getSignerAddresses(validators),
  //     powers,
  //     1,
  //     peggyId
  //   );

  //   const contractCheckpoint = await hashingContract.lastCheckpoint();
  //   const externalCheckpoint = makeCheckpoint(
  //     await getSignerAddresses(validators),
  //     powers,
  //     1,
  //     peggyId
  //   );

  //   expect(contractCheckpoint === externalCheckpoint);

  //   await hashingContract.JustSaveEverything(
  //     await getSignerAddresses(validators),
  //     powers,
  //     1
  //   );

  //   await hashingContract.JustSaveEverythingAgain(
  //     await getSignerAddresses(validators),
  //     powers,
  //     1
  //   );
  // });
});
