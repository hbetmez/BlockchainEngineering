import asyncio
import hashlib
import multiprocessing
import os
import struct
import time

from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.payload import Payload
from ipv8.peer import Peer
from ipv8.util import run_forever
from ipv8_service import IPv8
import logging
from ipv8.util import run_forever

# --- CONFIGURATION ---
EMAIL = "m.grigore@student.tudelft.nl"
GITHUB_URL = "https://github.com/mateigrigore/blockchain-engineering"
COMMUNITY_ID = bytes.fromhex("4c61623247726f75705369676e696e6732303236")
SERVER_PUBLIC_KEY = bytes.fromhex(
    "4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3ddb6c1d82011a7f101553cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b8401f5f683031e60c96"
)
PEER2_PK = bytes.fromhex(
    "307e301006072a8648ce3d020106052b81040024036a0004015dfcc38f77c3f489f715f210d18fad35f315070282a1265b6994f4574b6c504bb592fbdf1a64f750ab3c8a5cfd125cc78b2fd40060835b78c17cb5f53d8e3626edc200630359a15acff13ce97eacf3e969b97fb62afbaee8f0d1495eddee367352e0e33d25d90d"
)

PEER3_PK = bytes.fromhex(
    "4c69624e61434c504b3a78b3a426b383064e29658b74b5e75816caf39d6fbc5c6aab11f22f91064a873857a14d2c997e1ff7387da6b2a69ee32bf70e379325eeeb2983492fd20c525735"
)

GROUP_ID = "da32f81bd9ac8a93"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_PATH = os.path.join(BASE_DIR, ".", "my_peer_key.pem")

# disable logging

logging.getLogger("ipv8").setLevel(logging.CRITICAL)
logging.getLogger("Lab2Community").setLevel(logging.CRITICAL)
logging.getLogger("PoWCommunity").setLevel(logging.CRITICAL)


# ---------------------

def sign_with_private_key(nonce: bytes):
    with open("my_peer_key.pem", "rb") as key_file:
        private_key = default_eccrypto.key_from_private_bin(key_file.read())

    return private_key.sign(nonce)


class RegisterPayload(Payload):
    msg_id = 1
    format_list = ["varlenH", "varlenH", "varlenH"]

    def __init__(self, member1_key: bytes, member2_key: bytes, member3_key: bytes):
        super().__init__()
        self.member1_key = member1_key
        self.member2_key = member2_key
        self.member3_key = member3_key

    def to_pack_list(self) -> list[tuple]:
        return [
            ("varlenH", self.member1_key),
            ("varlenH", self.member2_key),
            ("varlenH", self.member3_key),
        ]

    @classmethod
    def from_unpack_list(cls, member1_key: bytes, member2_key: bytes, member3_key: bytes):
        return cls(member1_key, member2_key, member3_key)


class RegisterResponsePayload(Payload):
    msg_id = 2
    format_list = ["?", "varlenHutf8", "varlenHutf8"]

    def __init__(self, success: bool, group_id: str, message: str):
        super().__init__()
        self.success = success
        self.group_id = group_id
        self.message = message

    def to_pack_list(self) -> list[tuple]:
        return [
            ("?", self.success),
            ("varlenHutf8", self.group_id),
            ("varlenHutf8", self.message),
        ]

    @classmethod
    def from_unpack_list(cls, success: bool, group_id: str, message: str):
        return cls(success, group_id, message)


class ChallengeRequest(Payload):
    msg_id = 3
    format_list = ["varlenHutf8"]

    def __init__(self, group_id: str):
        super().__init__()
        self.group_id = group_id

    def to_pack_list(self) -> list[tuple]:
        return [
            ("varlenHutf8", self.group_id),
        ]

    @classmethod
    def from_unpack_list(cls, group_id: str):
        return cls(group_id)


class ChallengeResponse(Payload):
    msg_id = 4
    format_list = ["varlenH", "q", "d"]

    def __init__(self, nonce: bytes, round_number: int, deadline: float):
        super().__init__()
        self.nonce = nonce
        self.round_number = round_number
        self.deadline = deadline

    def to_pack_list(self) -> list[tuple]:
        return [
            ("varlenH", self.nonce),
            ("q", self.round_number),
            ("d", self.deadline),
        ]

    @classmethod
    def from_unpack_list(cls, nonce: bytes, round_number: int, deadline: float):
        return cls(nonce, round_number, deadline)


class SignatureBundle(Payload):
    msg_id = 5
    format_list = ["varlenHutf8", "q", "varlenH", "varlenH", "varlenH"]

    def __init__(self, group_id: str, round_number: int, sig1: bytes, sig2: bytes, sig3: bytes):
        super().__init__()
        self.group_id = group_id
        self.round_number = round_number
        self.sig1 = sig1
        self.sig2 = sig2
        self.sig3 = sig3

    def to_pack_list(self) -> list[tuple]:
        return [
            ("varlenHutf8", self.group_id),
            ("q", self.round_number),
            ("varlenH", self.sig1),
            ("varlenH", self.sig2),
            ("varlenH", self.sig3),
        ]

    @classmethod
    def from_unpack_list(cls, group_id: str, round_number: int, sig1: bytes, sig2: bytes, sig3: bytes):
        return cls(group_id, round_number, sig1, sig2, sig3)


class RoundResultPayload(Payload):
    msg_id = 6
    format_list = ["?", "q", "q", "varlenHutf8"]

    def __init__(self, success: bool, round_number: int, rounds_completed: int, message: str):
        super().__init__()
        self.success = success
        self.round_number = round_number
        self.rounds_completed = rounds_completed
        self.message = message

    def to_pack_list(self) -> list[tuple]:
        return [
            ("?", self.success),
            ("q", self.round_number),
            ("q", self.rounds_completed),
            ("varlenHutf8", self.message),
        ]

    @classmethod
    def from_unpack_list(cls, success: bool, round_number: int, rounds_completed: int, message: str):
        return cls(success, round_number, rounds_completed, message)


class NoncePayload(Payload):
    msg_id = 7
    format_list = ["varlenH"]

    def __init__(self, nonce: bytes):
        super().__init__()
        self.nonce = nonce

    def to_pack_list(self) -> list[tuple]:
        return [
            ("varlenH", self.nonce),
        ]

    @classmethod
    def from_unpack_list(cls, nonce: bytes):
        return cls(nonce)


class SignedNoncePayload(Payload):
    msg_id = 8
    format_list = ["varlenH"]

    def __init__(self, signed_nonce: bytes):
        super().__init__()
        self.signed_nonce = signed_nonce

    def to_pack_list(self) -> list[tuple]:
        return [
            ("varlenH", self.signed_nonce),
        ]

    @classmethod
    def from_unpack_list(cls, signed_nonce: bytes):
        return cls(signed_nonce)


class RoundFinished(Payload):
    msg_id = 9
    format_list = ["q"]

    def __init__(self, round_number: int):
        super().__init__()
        self.round_number = round_number

    def to_pack_list(self) -> list[tuple]:
        return [
            ("q", self.round_number),
        ]

    @classmethod
    def from_unpack_list(cls, round_number: int):
        return cls(round_number)


class PoWCommunity(Community):
    community_id = COMMUNITY_ID

    def __init__(self, settings: CommunitySettings):
        super().__init__(settings)

        self.add_message_handler(4, self.on_challenge_response)
        self.add_message_handler(6, self.on_round_result)
        self.add_message_handler(7, self.on_receive_nonce)
        self.add_message_handler(8, self.on_receive_signed_nonce)
        self.add_message_handler(9, self.on_confirmation)

        # self.add_message_handler(2, self.on_server_response)

        self.server_peer: Peer | None = None
        self.peer3: Peer | None = None
        self.peer2: Peer | None = None
        self.sig1: bytes | None = None
        self.sig2: bytes | None = None
        self.my_sig: bytes | None = None
        self.round: int = 0

    def find_peer(self, public_key: bytes) -> Peer | None:
        """Find the server peer by matching its public key."""
        for peer in self.get_peers():
            if peer.public_key.key_to_bin() == public_key:

                if public_key == SERVER_PUBLIC_KEY:
                    self.server_peer = peer
                elif public_key == PEER3_PK:
                    self.peer3 = peer
                elif public_key == PEER2_PK:
                    self.peer2 = peer

                return peer
        return None

    def send_challenge_request(self, peer: Peer, group_id: str):
        self.ez_send(peer, ChallengeRequest(group_id))

    def send_nonce(self, peer: Peer, nonce: bytes):
        self.ez_send(peer, NoncePayload(nonce))

    def send_signed_nonce(self, peer: Peer, signed_nonce: bytes):
        self.ez_send(peer, SignedNoncePayload(signed_nonce))

    def send_submission(self, peer: Peer, group_id: str, round_number: int, sig1: bytes, sig2: bytes, sig3: bytes):
        self.ez_send(peer, SignatureBundle(group_id, round_number, sig1, sig2, sig3))

    def send_confirmation(self, peer: Peer, round_number: int):
        self.ez_send(peer, RoundFinished(round_number))

    @lazy_wrapper(ChallengeResponse)
    def on_challenge_response(self, peer: Peer, payload):
        print(f"Received challenge: round_number={payload.round_number}, deadline={payload.deadline}")
        if peer.public_key.key_to_bin() != SERVER_PUBLIC_KEY:
            print(f"Ignoring response from unknown peer")
            return

        self.my_sig = sign_with_private_key(payload.nonce)

        self.send_nonce(self.peer2, payload.nonce)
        self.send_nonce(self.peer3, payload.nonce)

    @lazy_wrapper(RoundResultPayload)
    def on_round_result(self, peer: Peer, payload):
        print(f"Received round result: success={payload.success}, round_number={payload.round_number}, rounds_completed={payload.rounds_completed}, message='{payload.message}'")
        if peer.public_key.key_to_bin() != SERVER_PUBLIC_KEY:
            print(f"Ignoring response from unknown peer")
            return

        if payload.success:
            self.sig1 = None
            self.sig2 = None
            self.my_sig = None
            self.round += 1
            if payload.rounds_completed == 3:
                print(payload.message)
            else:
                # send confirmation to peers
                self.send_confirmation(self.peer3, payload.round_number)
                self.send_confirmation(self.peer2, payload.round_number)

    @lazy_wrapper(NoncePayload)
    def on_receive_nonce(self, peer: Peer, payload):
        print(f"Received nonce from peer: {peer.public_key.key_to_bin().hex()[:30]}...")
        if peer.public_key.key_to_bin() not in [PEER3_PK, PEER2_PK]:
            print(f"Ignoring response from unknown peer")
            return

        signed_nonce = sign_with_private_key(payload.nonce)

        self.send_signed_nonce(peer, signed_nonce)

    @lazy_wrapper(SignedNoncePayload)
    def on_receive_signed_nonce(self, peer: Peer, payload):
        print(f"Received signed nonce from peer: {peer.public_key.key_to_bin().hex()[:30]}...")
        if peer.public_key.key_to_bin() not in [PEER3_PK, PEER2_PK]:
            print(f"Ignoring response from unknown peer")
            return

        if peer == self.peer3:
            self.sig1 = payload.signed_nonce
            if self.sig2 is not None:
                self.send_submission(self.server_peer, GROUP_ID, self.round, self.sig1, self.sig2, self.my_sig)

        if peer == self.peer2:
            self.sig2 = payload.signed_nonce
            if self.sig1 is not None:
                self.send_submission(self.server_peer, GROUP_ID, self.round, self.sig1, self.sig2, self.my_sig)

    @lazy_wrapper(RoundFinished)
    def on_confirmation(self, peer: Peer, payload):
        if peer.public_key.key_to_bin() not in [PEER3_PK, PEER2_PK]:
            print(f"Ignoring response from unknown peer")
            return

        self.round = payload.round_number + 1

        if self.round == 1:
            self.send_challenge_request(self.server_peer, GROUP_ID)


async def start_client():
    """Start the IPv8 client, mine a nonce, and submit it to the server."""

    if not os.path.exists(KEY_PATH):
        raise FileNotFoundError(KEY_PATH)

    builder = ConfigBuilder()
    builder.clear_keys()
    builder.add_key("my peer", "curve25519", KEY_PATH)
    builder.clear_overlays()
    builder.add_overlay(
        "PoWCommunity",
        "my peer",
        [WalkerDefinition(Strategy.RandomWalk, 20, {"timeout": 3.0})],
        default_bootstrap_defs,
        {},
        [],
    )

    ipv8 = IPv8(builder.finalize(), extra_communities={"PoWCommunity": PoWCommunity})
    await ipv8.start()

    # await ipv8.run_forever()

    community: PoWCommunity = ipv8.get_overlay(PoWCommunity)

    # Wait for server discovery
    print("Waiting for server peer...")
    server = None
    while server is None:
        await asyncio.sleep(1.0)
        server = community.find_peer(SERVER_PUBLIC_KEY)
        community.server_peer = server
    print(f"Server found: {server}")

    print("Waiting for peer...")
    peer3 = None
    while peer3 is None:
        await asyncio.sleep(1.0)
        peer3 = community.find_peer(PEER3_PK)
        community.peer3 = peer3
    print(f"Server found: {peer3}")

    print("Waiting for peer...")
    peer2 = None
    while peer2 is None:
        await asyncio.sleep(1.0)
        peer2 = community.find_peer(PEER2_PK)
        community.peer2 = peer2
    print(f"Server found: {peer2}")

    # First peer sends request
    self.send_challenge_request(server, GROUP_ID)
    # while self.round != 4:
    #     await asyncio.sleep(1.0)

    # Wait for response
    print("Waiting for server response...")
    await asyncio.sleep(30)

    await run_forever()


if __name__ == "__main__":
    multiprocessing.freeze_support()
    asyncio.run(start_client())

