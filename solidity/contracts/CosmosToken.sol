pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract ComsosERC20 is ERC20 {
	constructor(address peggyAddress) public ERC20() {
		_mint(peggyAddress, type(uint256).max);
	}
}
