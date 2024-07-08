// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {ImageID} from "./ImageID.sol"; // auto-generated contract after running `cargo build`.

/// @title A starter application using RISC Zero.
/// @dev This contract demonstrates one pattern for offloading the computation of an expensive
///      or difficult to implement function to a RISC Zero guest running on Bonsai.
contract EcdsaVerify {
    /// @notice RISC Zero verifier contract address.
    IRiscZeroVerifier public immutable verifier;
    /// @notice Image ID of the only zkVM binary to accept verification from.
    ///         The image ID is similar to the address of a smart contract.
    ///         It uniquely represents the logic of that guest program,
    ///         ensuring that only proofs generated from a pre-defined guest program
    ///         (in this case, checking if a number is even) are considered valid.
    bytes32 public constant imageId = ImageID.ECDSA_VERIFY_ID;

    /// @notice If the last ECDSA signature verification was successful.
    bool public valid;

    /// @notice Initialize the contract, binding it to a specified RISC Zero verifier.
    constructor(IRiscZeroVerifier _verifier) {
        verifier = _verifier;
        valid = false;
    }

    function set(
        uint256 msgHash,
        uint256 sigS,
        uint256 sigR,
        uint256 pubKey,
        bytes calldata seal
    ) public {
        // Construct the expected journal data. Verify will fail if journal does not match.
        bytes memory journal = abi.encode(msgHash, sigS, sigR, pubKey);
        verifier.verify(seal, imageId, sha256(journal));
        valid = true;
    }

    /// @notice Returns the last verification result.
    function get() public view returns (bool) {
        return valid;
    }
}
