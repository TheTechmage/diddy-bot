import json
import uuid
import os
from typing import Optional
import attr
import traceback
import aiohttp
import asyncio
import websockets
import logging
import didcomm_messaging

from did_peer_2 import KeySpec, generate
from didcomm.message import Message as DIDCommMessage
from pydid.did import DID
import sys

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



class Bot:
    """A basic "bot" framwork to design around.
    """

    async def handle_command(self, command: str, message: Message):
        """Handles "commands" sent via basic message.

        Args:
            command (str): command, equivalant to message.body["content"]
            message (Message): message
        """
        match command.lower().strip().split()[0]:
            case "hello":
                print(message)
                #await self.sendBasicMessage(message.frm, "Well howdy there partner!")
            case "haiku":
                pass
                #await self.sendBasicMessage(
                #    message.frm,
                #    "Glorious leaping,\nSurprisingly didcomm smiles,\nwatching the kitten",
                #)
            case "c2f":
                try:
                    c = float(command.strip().split()[1])
                    f = c * (9 / 5) + 32
                    await self.sendBasicMessage(
                        message.frm, f"{c} Celcius is {f} Fahrenheight"
                    )
                except Exception:
                    await self.sendBasicMessage(
                        message.frm, "Invalid command, try `c2f 32.5`"
                    )
            case "f2c":
                try:
                    f = float(command.strip().split()[1])
                    c = (5 / 9) * (f - 32)
                    await self.sendBasicMessage(
                        message.frm, f"{f} Fahrenheight is {c} Celcius"
                    )
                except Exception:
                    await self.sendBasicMessage(
                        message.frm, "Invalid command, try `c2f 32.5`"
                    )
            case _:
                logger.info("Received message %s", command.replace('\n', ' ').replace('\r', ''))
                print(message)

    async def handle_message(self, msg_type: str, message: Message):
        """Handles DIDComm messages based on msg_type.

        Args:
            msg_type (str): msg_type
            message (Message): message
        """
        match msg_type:
            case "https://didcomm.org/basicmessage/2.0/message":
                await self.handle_command(message.body["content"], message)
            case "https://didcomm.org/trust-ping/2.0/ping":
                if message.body.get("response_requested") == True:
                    new_message = Message(
                        type="https://didcomm.org/trust-ping/2.0/ping-response",
                        body={},
                        id=str(uuid.uuid4()),
                        thid=message.id,
                        frm=self.did,
                        to=[message.frm],
                    )
                    await self.sendMessage(new_message, target=message.frm)
            case "https://didcomm.org/user-profile/1.0/request-profile":
                new_message = Message(
                    type="https://didcomm.org/user-profile/1.0/profile",
                    body={
                        "profile": {
                            "displayName": f"Frostyfrog (script) @ Response",
                            "description": "I'm a bot written in python",
                        },
                    },
                    id=str(uuid.uuid4()),
                    frm=self.did,
                    to=[message.frm],
                )
                await self.sendMessage(new_message, target=message.frm)
            case _:
                logger.error("UNKNOWN MESSAGE RECEIVED! %s", msg_type)

    async def fetch_messages(self):
        """Fetch new messages from the mediator that have yet to be handled.
        """
        message = Message(
            type="https://didcomm.org/messagepickup/3.0/status-request",
            id=str(uuid.uuid4()),
            body={},
            frm=self.my_did,
            to=[MEDIATOR_DID],
        )
        message = await self.sendMessage(message, target=MEDIATOR_DID)

        if message.body["message_count"] > 0:
            message = Message(
                type="https://didcomm.org/messagepickup/3.0/delivery-request",
                id=str(uuid.uuid4()),
                body={
                    "limit": message.body["message_count"],
                },
                frm=self.my_did,
                to=[MEDIATOR_DID],
            )
            message = await self.sendMessage(message, target=MEDIATOR_DID)
            for attach in message.attachments:
                logger.info("Received message %s", attach.id[:-58])
                unpacked = await self.get_didcomm().packaging.unpack(json.dumps(attach.data.json))
                msg = unpacked[0].decode()
                msg =  Message.from_json(msg)
                await self.handle_message(msg.type, msg)
                if msg.type == "https://didcomm.org/basicmessage/2.0/message":
                    logmsg = msg.body['content'].replace('\n', ' ').replace('\r', '')
                    logger.info(f"Got message: {logmsg}")
                message = Message(
                    type="https://didcomm.org/messagepickup/3.0/messages-received",
                    id=str(uuid.uuid4()),
                    body={
                        "message_id_list": [msg.id for msg in message.attachments],
                    },
                    frm=self.my_did,
                    to=[MEDIATOR_DID],
                )
                message = await self.sendMessage(message, target=MEDIATOR_DID)

                return

    async def sendMessage(
        self, message: Message, target: DID, ws: websockets.connect | None = None
    ):
        """Send a message to another DIDComm agent.

        Args:
            message (Message): message
            target (DID): target
            ws (websockets.connect | None): ws
        """

        message_wrapper = message
        message = message.as_dict()
        packy = await self.get_didcomm().pack(
            message=message,
            to=target,
            frm=self.my_did if target == MEDIATOR_DID else self.did,
        )
        packed = packy.message
        endpoint = packy.get_endpoint("http")

        if ws:
            logger.info("Sending via websocket %s", packed)
            await ws.send(packed)
            logger.debug("Sent over websocket")
            return

        async with aiohttp.ClientSession() as session:
            print("posting message type", message_wrapper.type)
            print("posting to ", endpoint)
            async with session.post(endpoint, data=packed) as resp:
                packed = await resp.text()
                if len(packed) > 0:
                    unpacked = await self.get_didcomm().packaging.unpack(packed)
                    msg = unpacked[0].decode()
                    print("UNPACKED MESSAGE FROM REMOTE", msg)
                    return Message.from_json(msg)
        return

    async def sendBasicMessage(self, target_did: DID, message: str):
        """Send a basicmessage to the target_did.

        Args:
            target_did (DID): target_did
            message (str): message
        """
        message = Message(
            type="https://didcomm.org/basicmessage/2.0/message",
            body={"content": message},
            id=str(uuid.uuid4()),
            frm=self.did,
            to=[target_did],
        )
        await self.sendMessage(message, target_did)

    async def handle_websocket(self):
        """Handle websocket messages.
        """
        async with self.websocket as websocket:
            # await websocket.send("msg")
            logger.info("Listening on websocket")
            message = Message(
                type="https://didcomm.org/messagepickup/3.0/live-delivery-change",
                id=str(uuid.uuid4()),
                body={
                    "live_delivery": True,
                },
                frm=self.my_did,
                to=[MEDIATOR_DID],
            )
            message = await self.sendMessage(message, target=MEDIATOR_DID, ws=websocket)
            logger.info("Requested live delivery")
            # async for message in websocket:
            while True:
                message = await websocket.recv()
                logger.info("Got message over websocket")
                try:
                    unpacked = await self.get_didcomm().packaging.unpack(message)
                    msg = unpacked[0].decode()
                    msg = Message.from_json(msg)
                    # logger.info("Received message %s", unpacked_msg.message)
                    logger.info("Received websocket message %s", msg.type)
                    if msg.frm != MEDIATOR_DID:
                        await self.handle_message(msg.type, msg)
                except Exception as err:
                    logger.error("Error encountered")
                    logger.exception(err)
                    pass
            await websocket.close()

    def get_didcomm(self):
        return self._DMP

    async def start(self):
        """Start up the "bot" application and begin sending/receiving messages.
        """

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
                #{
                #    "type": "DIDCommMessaging",
                #    "serviceEndpoint": {
                #        "uri": "https://webhook.site/47c6023d-8a74-4591-a308-36452ecb1859",
                #        "accept": [
                #        "didcomm/v2"
                #        ],
                #        "routingKeys": []
                #    }
                #}
            ],
        )
        self.my_did = did

        doc = await resolver.resolve_and_parse(did)

        await secrets.add_secret(AskarSecretKey(verkey, f"{did}#key-1"))
        await secrets.add_secret(AskarSecretKey(xkey, f"{did}#key-2"))
        await secrets.add_secret(AskarSecretKey(verkey, doc.authentication[0]))
        await secrets.add_secret(AskarSecretKey(xkey, doc.key_agreement[0]))


        DMP = didcomm_messaging.DIDCommMessaging(crypto=crypto, secrets=secrets, resolver=resolver, packaging=packer, routing=router)
        self._DMP = DMP

        message = Message(
            type="https://didcomm.org/coordinate-mediation/3.0/mediate-request",
            id=str(uuid.uuid4()),
            body={},
            frm=self.my_did,
            to=[MEDIATOR_DID],
        )
        message = await self.sendMessage(message, target=MEDIATOR_DID)

        if message.type == "https://didcomm.org/coordinate-mediation/3.0/mediate-grant":
            mediator_did = message.body["routing_did"][0]
            # resolved_did = resolve(mediator_did)
            self.did = generate(
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
                            "uri": mediator_did,
                            "accept": ["didcomm/v2"],
                        },
                    }
                ],
            )
            print("mediated did: ", self.did)
            doc = await resolver.resolve_and_parse(self.did)
            await secrets.add_secret(AskarSecretKey(verkey, f"{self.did}#key-1"))
            await secrets.add_secret(AskarSecretKey(xkey, f"{self.did}#key-2"))
            await secrets.add_secret(AskarSecretKey(verkey, doc.authentication[0]))
            await secrets.add_secret(AskarSecretKey(xkey, doc.key_agreement[0]))
        message = Message(
           type="https://didcomm.org/coordinate-mediation/3.0/recipient-update",
           id=str(uuid.uuid4()),
           body={
               "updates": [
                   {
                       "recipient_did": self.did,
                       "action": "add",
                   },
               ],
           },
           frm=self.my_did,
           to=[MEDIATOR_DID],
        )
        message = await self.sendMessage(message, target=MEDIATOR_DID)

        await self.fetch_messages()

        target_did = input("DID to message (blank for diddy-bot)> ")
        if not target_did.startswith("did:"):
            target_did = OLD_BOT_DID

        new_message = Message(
            type="https://didcomm.org/user-profile/1.0/profile",
            body={
                "profile": {
                    "displayName": f"Frostyfrog (script) @ Initiator",
                    "description": "I'm a bot written in python",
                },
            },
            id=str(uuid.uuid4()),
            frm=self.did,
            to=[target_did],
        )
        await self.sendMessage(new_message, target=target_did)

        await self.sendBasicMessage(target_did, "Starting up agent")
        message = Message(
            type="https://didcomm.org/basicmessage/2.0/message",
            id=str(uuid.uuid4()),
            body={"content": input("Message to send> ")},
            frm=self.did,
            lang="en",
            to=[target_did],
        )
        await self.sendMessage(message, target=target_did)
        await asyncio.sleep(1)
        await self.fetch_messages()
        await self.sendMessage(message, target=target_did)
        await self.sendMessage(message, target=target_did)


        mediator_websocket = None
        async def activate_websocket():
            async def get_service(did, protocol):
                did_doc = await self.get_didcomm().resolver.resolve_and_parse(did)
                services = []
                if did_doc.service:  # service is not guaranteed to exist
                    for did_service in did_doc.service:
                        if "didcomm/v2" in did_service.service_endpoint.accept:
                            services.append(did_service)
                services = [
                    service
                    for service in services
                    if service.service_endpoint.uri.startswith(protocol)
                ]
                return services

            mediator_websocket = await get_service(MEDIATOR_DID, "ws")
            mediator_websocket = list(mediator_websocket)[0]
            logger.info("Mediator Websocket Address: %s", mediator_websocket)
            if mediator_websocket:
                logger.info("Found Mediation websocket, connecting")
                self.websocket = websockets.connect(
                    uri=mediator_websocket.service_endpoint.uri
                )
                self.websock_proc = asyncio.create_task(self.handle_websocket())


        print("%%%%%%%%%%%%%%%%%%%%%%%")
        print("mediated did: ", self.did)
        logger.info("mediated did: %s", self.did)
        print("%%%%%%%%%%%%%%%%%%%%%%%")

        while True:
            await asyncio.sleep(5)
            if not mediator_websocket:
                await self.fetch_messages()
            #await self.sendMessage(message, target=target_did)


async def main():
    try:
        bot = Bot()
        await bot.start()
    except Exception as e:
        print("Exception?", e)
        print(traceback.format_exc())


loop = asyncio.get_event_loop()
tasks = [loop.create_task(main())]
loop.run_until_complete(asyncio.wait(tasks))
loop.close()
