pragma solidity ^0.6.6;
import "@nomiclabs/buidler/console.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract Caller {
	uint256 foo = 3;
	uint256 bar = 5;

	function callOut(
		address _callee,
		address _tokenContract,
		address _destination
	) public {
		console.log("in caller");
		console.log(msg.sender);

		// Regular call
		// Callee(_callee).callIn(_tokenContract, _destination);

		// delegateCall
		_callee.delegatecall(
			abi.encodeWithSignature("callIn(address,address)", _tokenContract, _destination)
		);
	}
}

contract Callee {
	uint256 foo = 4;
	uint256 bar;
	uint256 baz = 8;

	function callIn(address _tokenContract, address _destination) public {
		console.log("in callee");
		console.log(msg.sender);
		console.log("foo", foo);
		console.log("bar", bar);
		console.log("baz", baz);
		baz = 16;
		console.log("baz", baz);
		IERC20(_tokenContract).transfer(_destination, 1);
	}
}
