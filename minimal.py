from typing import Optional
import aiohttp
import asyncio
import attr
import didcomm_messaging
import json
import logging
import os
import sys
import traceback
import uuid
import websockets

from did_peer_2 import KeySpec, generate
from didcomm.message import Message as DIDCommMessage
from pydid.did import DID
from pydid import DIDDocument

from aries_askar import Key, KeyAlg
from didcomm_messaging.crypto.backend.askar import AskarCryptoService, AskarSecretKey
from didcomm_messaging.crypto.backend.basic import InMemorySecretsManager
from didcomm_messaging.packaging import PackagingService
from didcomm_messaging.multiformats import multibase
from didcomm_messaging.multiformats import multicodec
from didcomm_messaging.resolver.peer import Peer2, Peer4
from didcomm_messaging.resolver import PrefixResolver
from didcomm_messaging.routing import RoutingService

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
root = logging.getLogger()
root.setLevel(LOG_LEVEL)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(LOG_LEVEL)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
root.addHandler(handler)

logging.getLogger("didcomm").setLevel(logging.WARN)
logger = logging.getLogger(__name__)

MEDIATOR_DID = "did:peer:2.Vz6MktASEQH6L6F68KwR45MiMJQMC1vv9RotMp8iwzFCfKksZ.Ez6LSjtPCo1WL8JHzibm6iLaHU46Eahoaj6BVDezuVrZX6QZ1.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHBzOi8vZGV2LmNsb3VkbWVkaWF0b3IuaW5kaWNpb3RlY2guaW8vbWVzc2FnZSIsImEiOlsiZGlkY29tbS92MiIsImRpZGNvbW0vYWlwMjtlbnY9cmZjMTkiXSwiciI6W119fQ.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6IndzczovL3dzLmRldi5jbG91ZG1lZGlhdG9yLmluZGljaW90ZWNoLmlvL3dzIiwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmMxOSJdLCJyIjpbXX19"

OLD_BOT_DID = 'did:peer:2.Ez6LSg7dftRECRoeLvHx5FXG77SLL2GGHX5C2UbWbQTrQw8xb.Vz6MksRzg3RHj8PK7dJb53TgynsCDyKMQfQfG7oP5ggrAuFa1.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6ImRpZDpwZWVyOjIuVno2TWt0QVNFUUg2TDZGNjhLd1I0NU1pTUpRTUMxdnY5Um90TXA4aXd6RkNmS2tzWi5FejZMU2p0UENvMVdMOEpIemlibTZpTGFIVTQ2RWFob2FqNkJWRGV6dVZyWlg2UVoxLlNleUowSWpvaVpHMGlMQ0p6SWpwN0luVnlhU0k2SW1oMGRIQnpPaTh2WkdWMkxtTnNiM1ZrYldWa2FXRjBiM0l1YVc1a2FXTnBiM1JsWTJndWFXOHZiV1Z6YzJGblpTSXNJbUVpT2xzaVpHbGtZMjl0YlM5Mk1pSXNJbVJwWkdOdmJXMHZZV2x3TWp0bGJuWTljbVpqTVRraVhTd2ljaUk2VzExOWZRLlNleUowSWpvaVpHMGlMQ0p6SWpwN0luVnlhU0k2SW5kemN6b3ZMM2R6TG1SbGRpNWpiRzkxWkcxbFpHbGhkRzl5TG1sdVpHbGphVzkwWldOb0xtbHZMM2R6SWl3aVlTSTZXeUprYVdSamIyMXRMM1l5SWl3aVpHbGtZMjl0YlM5aGFYQXlPMlZ1ZGoxeVptTXhPU0pkTENKeUlqcGJYWDE5IiwiYSI6WyJkaWRjb21tL3YyIl19fQ'

@attr.s(auto_attribs=True)
class Message(DIDCommMessage):
    lang: Optional[str] = None
    def __init__(cls, *args, lang=None, **kwargs):
        super().__init__(*args, **kwargs)
        cls.lang = lang

class CompatibilityPrefixResolver(PrefixResolver):
    """stub."""

    async def resolve_and_parse(self, did: str) -> DIDDocument:
        """Resolve a DID and parse the DID document."""
        doc = await self.resolve(did)
        #return DIDDocument.deserialize(doc)
        id_map = {}
        def set_id(method):
            new_id = method["publicKeyMultibase"][1:9]
            id_map[method["id"]] = new_id
            method["id"] = did + "#" + new_id
            return method
        doc["verificationMethod"] = [
            set_id(method) for method in doc["verificationMethod"]
        ]
        doc["authentication"] = [
            did + "#" + id_map.get(id) for id in doc["authentication"]
        ]
        doc["keyAgreement"] = [did + "#" + id_map.get(id) for id in doc["keyAgreement"]]
        return DIDDocument.deserialize(doc)


async def main():
    crypto = AskarCryptoService()
    secrets = InMemorySecretsManager()
    resolver = CompatibilityPrefixResolver({"did:peer:2": Peer2(), "did:peer:4": Peer4()})
    packer = PackagingService(
        resolver, crypto, secrets
    )

    router = RoutingService(packaging=packer, resolver=resolver)

    verkey = Key.generate(KeyAlg.ED25519)
    xkey = Key.generate(KeyAlg.X25519)
    did = generate(
        [
            KeySpec.verification(
                multibase.encode(
                    multicodec.wrap("ed25519-pub", verkey.get_public_bytes()),
                    "base58btc",
                )
            ),
            KeySpec.key_agreement(
                multibase.encode(
                    multicodec.wrap("x25519-pub", xkey.get_public_bytes()), "base58btc"
                )
            ),
        ],
        [
            {
                "type": "DIDCommMessaging",
                "serviceEndpoint": {
                    "uri": "https://webhook.site/e918b05e-dcfd-4019-9d94-1bea5caac41a",
                    "accept": [
                    "didcomm/v2"
                    ],
                    "routingKeys": []
                }
            }
        ],
    )

    doc = await resolver.resolve_and_parse(did)

    await secrets.add_secret(AskarSecretKey(verkey, f"{did}#key-1"))
    await secrets.add_secret(AskarSecretKey(xkey, f"{did}#key-2"))
    await secrets.add_secret(AskarSecretKey(verkey, doc.authentication[0]))
    await secrets.add_secret(AskarSecretKey(xkey, doc.key_agreement[0]))

    async def sendMessage(
        dmp, fromdid, message: Message, target: DID
    ):
        """Send a message to another DIDComm agent.

        Args:
            message (Message): message
            target (DID): target
            ws (websockets.connect | None): ws
        """

        message_wrapper = message
        message = message.as_dict()
        packy = await dmp.pack(
            message=message,
            to=target,
            frm=fromdid,
        )
        packed = packy.message
        endpoint = packy.get_endpoint("http")

        async with aiohttp.ClientSession() as session:
            print("posting message type", message_wrapper.type)
            print("posting to ", endpoint)
            async with session.post(endpoint, data=packed) as resp:
                packed = await resp.text()
                if len(packed) > 0:
                    unpacked = await dmp.packaging.unpack(packed)
                    msg = unpacked[0].decode()
                    print("UNPACKED MESSAGE FROM REMOTE", msg)
                    return Message.from_json(msg)
        return


    DMP = didcomm_messaging.DIDCommMessaging(crypto=crypto, secrets=secrets, resolver=resolver, packaging=packer, routing=router)

    target_did = input("DID to message (blank for diddy-bot)> ")
    if not target_did.startswith("did:"):
        target_did = OLD_BOT_DID

    message = Message(
        type="https://didcomm.org/basicmessage/2.0/message",
        id=str(uuid.uuid4()),
        body={"content": input("Message to send> ")},
        frm=did,
        lang="en",
        to=[target_did],
    )
    print(await sendMessage(DMP, did, message, target=target_did))
    await asyncio.sleep(1)
    # We have no way of fetching messages, since we did not establish mediation.
    # await self.fetch_messages()


loop = asyncio.get_event_loop()
tasks = [loop.create_task(main())]
loop.run_until_complete(asyncio.wait(tasks))
loop.close()


# async def fetch_messages(self):
#     """Fetch new messages from the mediator that have yet to be handled.
#     """
#     message = Message(
#         type="https://didcomm.org/messagepickup/3.0/status-request",
#         id=str(uuid.uuid4()),
#         body={},
#         frm=self.my_did,
#         to=[MEDIATOR_DID],
#     )
#     message = await self.sendMessage(message, target=MEDIATOR_DID)

#     if message.body["message_count"] > 0:
#         message = Message(
#             type="https://didcomm.org/messagepickup/3.0/delivery-request",
#             id=str(uuid.uuid4()),
#             body={
#                 "limit": message.body["message_count"],
#             },
#             frm=self.my_did,
#             to=[MEDIATOR_DID],
#         )
#         message = await self.sendMessage(message, target=MEDIATOR_DID)
#         for attach in message.attachments:
#             logger.info("Received message %s", attach.id[:-58])
#             unpacked = await self.get_didcomm().packaging.unpack(json.dumps(attach.data.json))
#             msg = unpacked[0].decode()
#             msg =  Message.from_json(msg)
#             await self.handle_message(msg.type, msg)
#             if msg.type == "https://didcomm.org/basicmessage/2.0/message":
#                 logmsg = msg.body['content'].replace('\n', ' ').replace('\r', '')
#                 logger.info(f"Got message: {logmsg}")
#             message = Message(
#                 type="https://didcomm.org/messagepickup/3.0/messages-received",
#                 id=str(uuid.uuid4()),
#                 body={
#                     "message_id_list": [msg.id for msg in message.attachments],
#                 },
#                 frm=self.my_did,
#                 to=[MEDIATOR_DID],
#             )
#             message = await self.sendMessage(message, target=MEDIATOR_DID)

#             return
