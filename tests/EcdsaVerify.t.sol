// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.20;

import {RiscZeroCheats} from "risc0/test/RiscZeroCheats.sol";
import {console2} from "forge-std/console2.sol";
import {Test} from "forge-std/Test.sol";
import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";
import {EcdsaVerify} from "../contracts/EcdsaVerify.sol";
import {Elf} from "./Elf.sol"; // auto-generated contract after running `cargo build`.

contract EvenNumberTest is RiscZeroCheats, Test {
    EcdsaVerify public ecdsaVerify;

    function setUp() public {
        IRiscZeroVerifier verifier = deployRiscZeroVerifier();
        ecdsaVerify = new EcdsaVerify(verifier);
        assertEq(ecdsaVerify.get(), false);
    }

    function test_SetValid() public {
        uint256 msgHash = 0xd8a326473d017c4b8ed203ae4c7f9f596beb93f778e9a9190121f8c67c7926db;
        uint256 sigR = 0x151a57a7e03dd176ca7ff63a6619ec609ef5a96b52a3944d9524b1fded517e0d;
        uint256 sigS = 0x276953b4f52b401143846fb665b30bccba456c7eacc9b28dfd00e2d472e51360;
        uint256 pubKey = 0x39a3b9db34166ba7957fe9b28b4d47eb77a5a6db2a7d0167b36a61828145eafb;
        (, bytes memory seal) = prove(
            Elf.ECDSA_VERIFY_PATH,
            abi.encode(msgHash, sigS, sigR, pubKey)
        );

        ecdsaVerify.set(msgHash, sigS, sigR, pubKey, seal);
        assertEq(ecdsaVerify.get(), true);
    }
}
