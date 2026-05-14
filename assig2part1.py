import asyncio
from dataclasses import dataclass

from ipv8.community import Community
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload
from ipv8.peer import Peer
from ipv8.configuration import (
    ConfigBuilder, WalkerDefinition, BootstrapperDefinition,
    Strategy, Bootstrapper, DISPERSY_BOOTSTRAPPER,
)
from ipv8.messaging.payload_dataclass import DataClassPayloadWID
from ipv8_service import IPv8
import logging

logging.getLogger("ipv8").setLevel(logging.CRITICAL)
logging.getLogger("Lab2Community").setLevel(logging.CRITICAL)

# ── Member public keys ────────────────────────────────────────────────────

MEMBER1_KEY_HEX = "4c69624e61434c504b3aca9c493f737c67ecacba22f75974a176bb9e73f48f375d53536b8b4a082b4308e2ba9bad0af305536cba9a4c3de9352a10ed9e9afdddae3a95b8203133f3311a"
MEMBER2_KEY_HEX = "307e301006072a8648ce3d020106052b81040024036a0004015dfcc38f77c3f489f715f210d18fad35f315070282a1265b6994f4574b6c504bb592fbdf1a64f750ab3c8a5cfd125cc78b2fd40060835b78c17cb5f53d8e3626edc200630359a15acff13ce97eacf3e969b97fb62afbaee8f0d1495eddee367352e0e33d25d90d"
MEMBER3_KEY_HEX = "4c69624e61434c504b3a78b3a426b383064e29658b74b5e75816caf39d6fbc5c6aab11f22f91064a873857a14d2c997e1ff7387da6b2a69ee32bf70e379325eeeb2983492fd20c525735"

SERVER_KEY_HEX = (
    "4c69624e61434c504b3a82e33614a342774e084a"
    "f80835838d6dbdb64a537d3ddb6c1d82011a7f10"
    "1553cda40cf5fa0e0fc23abd0a9c4f81322282c5"
    "b34566f6b8401f5f683031e60c96"
)


# ── Payloads ──────────────────────────────────────────────────────────────────

# Outgoing — we construct it, DataClassPayloadWID is fine
@dataclass
class RegisterPayload(DataClassPayloadWID):
    """message_id = 1 — register the group."""
    msg_id = 1
    member1_key: bytes
    member2_key: bytes
    member3_key: bytes


# Incoming — use plain VariablePayload with explicit format_list.
# "?" = bool, "4H" = varlenH bytes field (2-byte length prefix).
# Do NOT use DataClassPayloadWID for payloads you receive — the dataclass
# __init__ signature confuses from_unpack_list in some IPv8 versions.
class RegisterResponsePayload(
    Payload):
    """message_id = 2 — server reply."""
    msg_id = 2
    format_list = ["?", "varlenH", "varlenH"]
    names       = ["success", "group_id", "message"]


# ── Community ─────────────────────────────────────────────────────────────────

class Lab2Community(Community):
    community_id = bytes.fromhex("4c61623247726f75705369676e696e6732303236")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.add_message_handler(RegisterResponsePayload, self.on_register_response)
        self.server_peer = None
        self.group_id: str | None = None

    def peer_added(self, peer: Peer) -> None:
        key_hex = peer.public_key.key_to_bin().hex()
        print(f"[debug] Peer found: {key_hex[:30]}...")
        if key_hex == SERVER_KEY_HEX:
            print("[+] Server peer identified!")
            self.server_peer = peer

    @lazy_wrapper(RegisterResponsePayload)
    def on_register_response(self, peer: Peer, payload: RegisterResponsePayload) -> None:
        if peer.public_key.key_to_bin().hex() != SERVER_KEY_HEX:
            print("[-] Response from unknown peer – ignored")
            return
        status   = "ACCEPTED" if payload.success else "REJECTED"
        group_id = payload.group_id.decode() if isinstance(payload.group_id, bytes) else payload.group_id
        message  = payload.message.decode()  if isinstance(payload.message,  bytes) else payload.message
        print(f"[server] {status}: {message}")
        if payload.success:
            self.group_id = group_id
            print(f"[+] Group ID: {self.group_id}")

    async def register_group(self) -> None:
        while self.server_peer is None:
            for peer in self.get_peers():
                if peer.public_key.key_to_bin().hex() == SERVER_KEY_HEX:
                    self.server_peer = peer
                    print("[+] Server found!")
                    break
            if self.server_peer is None:
                print(f"[*] Waiting for server... ({len(self.get_peers())} peers known)")
                await asyncio.sleep(2)

        m1 = bytes.fromhex(MEMBER1_KEY_HEX)
        m2 = bytes.fromhex(MEMBER2_KEY_HEX)
        m3 = bytes.fromhex(MEMBER3_KEY_HEX)

        print("[*] Sending group registration...")
        self.ez_send(self.server_peer, RegisterPayload(m1, m2, m3))


# ── Main ──────────────────────────────────────────────────────────────────────

async def main() -> None:
    builder = (
        ConfigBuilder()
        .set_port(8090)
        .add_key("my peer", "curve25519", "my_key.pem")
        .clear_overlays()
        .add_overlay(
            "Lab2Community",
            "my peer",
            [WalkerDefinition(Strategy.RandomWalk, 10, {"timeout": 3.0})],
            [BootstrapperDefinition(
                Bootstrapper.DispersyBootstrapper,
                DISPERSY_BOOTSTRAPPER["init"],
            )],
            {},
            [],
        )
    )

    ipv8 = IPv8(builder.finalize(), extra_communities={"Lab2Community": Lab2Community})
    await ipv8.start()

    community: Lab2Community = ipv8.get_overlay(Lab2Community)
    await community.register_group()

    await asyncio.sleep(10)
    await ipv8.stop()


if __name__ == "__main__":
    asyncio.run(main())