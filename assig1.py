import asyncio
import hashlib
import struct
from ipv8.community import Community
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload
from ipv8.peer import Peer
from ipv8.configuration import ConfigBuilder, WalkerDefinition, BootstrapperDefinition, Strategy, Bootstrapper, \
    DISPERSY_BOOTSTRAPPER
from ipv8_service import IPv8

# 1.  Message payloads

from dataclasses import dataclass
from ipv8.messaging.payload_dataclass import DataClassPayloadWID

@dataclass
class SubmitPayload(DataClassPayloadWID):
    msg_id = 1
    email:      str
    github_url: str
    nonce:      int

class ResponsePayload(VariablePayload):
    msg_id = 2
    format_list = ['?', 'varlenH']
    names = ['success', 'message']

# 2.  The community (overlay)

SERVER_KEY_HEX = (
    "4c69624e61434c504b3a86b23934a28d669c390e2d1fc0b0870706c4591cc0cb"
    "178bc5a811da6d87d27ef319b2638ef60cc8d119724f4c53a1ebfad919c3ac41"
    "36c501ce5c09364e0ebb"
)

class Lab1Community(Community):
    community_id = bytes.fromhex("2c1cc6e35ff484f99ebdfb6108477783c0102881")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.add_message_handler(ResponsePayload, self.on_response)
        self.server_peer = None
        self.submitted = False

    # peer discovery callback
    def peer_added(self, peer: Peer):
        key_hex = peer.public_key.key_to_bin().hex()
        print(f"[debug] Peer found: {key_hex[:30]}...")
        if key_hex == SERVER_KEY_HEX:
            print(f"[+] Server found!")
            self.server_peer = peer

    # receive response from server
    @lazy_wrapper(ResponsePayload)
    def on_response(self, peer: Peer, payload: ResponsePayload):
        if peer.public_key.key_to_bin().hex() != SERVER_KEY_HEX:
            print("[-] Response from unknown peer, ignored")
            return
        status = "ACCEPTED" if payload.success else "REJECTED"
        print(f"[server] {status}: {payload.message.decode()}")

    # send submission once server is known
    async def submit(self, email: str, github_url: str, nonce: int):
        while self.server_peer is None:
            # Actively scan current peers on every loop
            for peer in self.get_peers():
                key_hex = peer.public_key.key_to_bin().hex()
                print(f"[debug] Peer: {key_hex[:30]}...")
                if key_hex == SERVER_KEY_HEX:
                    self.server_peer = peer
                    print("[+] Server found!")
                    break

            if self.server_peer is None:
                print(f"[*] Waiting... ({len(self.get_peers())} peers known)")
                await asyncio.sleep(2)

        print(f"[*] Sending submission (nonce={nonce}) ...")
        self.ez_send(self.server_peer, SubmitPayload(email, github_url, nonce))


# 3.  Proof-of-Work mining

def mine(email: str, github_url: str, difficulty: int = 28) -> int:
    """
    Find the smallest nonce ≥ 0 such that:
      SHA256(email\ngithub_url\nnonce_8_bytes_big_endian)
    has `difficulty` leading zero bits.
    """
    prefix      = email.encode() + b"\n" + github_url.encode() + b"\n"
    target_byte  = difficulty // 8          # full zero bytes needed  = 3
    target_bits  = difficulty  % 8          # extra bits in next byte = 4  → byte < 16

    nonce = 1
    print(f"[*] Mining with difficulty={difficulty} ...")
    while True:
        digest = hashlib.sha256(prefix + struct.pack(">q", nonce)).digest()

        # Check full zero bytes
        if digest[:target_byte] == b"\x00" * target_byte:
            # Check the remaining bits in the next byte
            next_byte = digest[target_byte]
            if next_byte < (1 << (8 - target_bits)):
                print(f"[+] Nonce found: {nonce}  (hash: {digest.hex()})")
                return nonce

        nonce += 1
        if nonce % 1_000_000 == 0:
            print(f"... tried {nonce:,} nonces")


# 4.  Boot IPv8 and run

async def main():
    EMAIL      = "h.betmezoglu-1@student.tudelft.nl"
    GITHUB_URL = "https://github.com/hbetmez"

    # Mine locally first (no network needed yet)
    nonce = mine(EMAIL, GITHUB_URL)

    # Build IPv8 config, key is auto-generated and saved to my_key.pem
    builder = (
        ConfigBuilder()
        .set_port(8090)
        .add_key("my peer", "curve25519", "my_key.pem")
        .clear_overlays()
        .add_overlay(
            "Lab1Community",
            "my peer",
            [WalkerDefinition(Strategy.RandomWalk, 10, {"timeout": 3.0})],
            [BootstrapperDefinition(Bootstrapper.DispersyBootstrapper, DISPERSY_BOOTSTRAPPER["init"])],
            {},
            [],
        )
    )

    ipv8 = IPv8(builder.finalize(), extra_communities={"Lab1Community": Lab1Community})
    await ipv8.start()

    community = ipv8.get_overlay(Lab1Community)
    await community.submit(EMAIL, GITHUB_URL, nonce)

    # Keep running so we can receive the response
    await asyncio.sleep(10)
    await ipv8.stop()


if __name__ == "__main__":
    asyncio.run(main())