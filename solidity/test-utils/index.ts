import {Peggy} from "../typechain/Peggy";
import {TestERC20} from "../typechain/TestERC20";
import {ethers} from "@nomiclabs/buidler";
import {getSignerAddresses, makeCheckpoint} from "./pure";
import {Signer} from "ethers";

type DeployContractsOptions = {
    corruptSig?: boolean;
};

export async function deployContracts(
    peggyId: string = "foo",
    valAddresses: string[],
    powers: number[],
    powerThreshold: number,
    opts?: DeployContractsOptions
) {
    const TestERC20 = await ethers.getContractFactory("TestERC20");
    const testERC20 = (await TestERC20.deploy()) as TestERC20;

    const Peggy = await ethers.getContractFactory("Peggy");

    const checkpoint = makeCheckpoint(valAddresses, powers, 0, peggyId);
    const peggy = (await Peggy.deploy(
        testERC20.address,
        peggyId,
        powerThreshold,
        valAddresses,
        powers
    )) as Peggy;

    await peggy.deployed();

    return {peggy, testERC20, checkpoint};
}

export async function loadContracts() {
    const peggyAddr = "0x8858eeB3DfffA017D4BCE9801D340D36Cf895CCf"
    const erc20Addr = "0x7c2C195CD6D34B8F845992d380aADB2730bB9C6F"
    const peggy = (await ethers.getContractAt("Peggy", peggyAddr))
    const testERC20 = (await ethers.getContractAt("TestERC20", erc20Addr))
    return {peggy, testERC20};
}
