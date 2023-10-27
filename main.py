import json
import uuid
import os
import traceback
import requests
import asyncio
import didcomm
import websockets
import logging

#from did_peer_2 import resolve
from temp_libraries.monkey_patch import resolve
from did_peer_2 import KeySpec, generate
from didcomm.message import Message
from pydid.did import DID
import sys

from temp_libraries import monkey_patch
from temp_libraries.resolvers import get_resolver_config
from temp_libraries.secrets import SecretsManager

LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()
root = logging.getLogger()
root.setLevel(LOG_LEVEL)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(LOG_LEVEL)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

logging.getLogger('didcomm').setLevel(logging.WARN)
logger = logging.getLogger(__name__)

monkey_patch.patch()

from didcomm.unpack import unpack

MEDIATOR_DID = "did:peer:2.Ez6LSjtPCo1WL8JHzibm6iLaHU46Eahoaj6BVDezuVrZX6QZ1.Vz6MktASEQH6L6F68KwR45MiMJQMC1vv9RotMp8iwzFCfKksZ.SW3sidCI6ImRtIiwicyI6Imh0dHBzOi8vZGV2LmNsb3VkbWVkaWF0b3IuaW5kaWNpb3RlY2guaW8vbWVzc2FnZSIsInIiOltdLCJhIjpbImRpZGNvbW0vdjIiLCJkaWRjb21tL2FpcDI7ZW52PXJmYzE5Il19LHsidCI6ImRtIiwicyI6IndzczovL3dzLmRldi5jbG91ZG1lZGlhdG9yLmluZGljaW90ZWNoLmlvL3dzIiwiciI6W10sImEiOlsiZGlkY29tbS92MiIsImRpZGNvbW0vYWlwMjtlbnY9cmZjMTkiXX1d"


class Bot:
    async def handle_command(self, command: str, message: Message):
        match command.lower().strip().split()[0]:
            case "hello":
                print(message)
                await self.sendBasicMessage(message.frm, "Well howdy there partner!")
            case "haiku":
                await self.sendBasicMessage(message.frm, "Glorious leaping,\nSurprisingly didcomm smiles,\nwatching the kitten")
            case "c2f":
                try:
                    c = float(command.strip().split()[1])
                    f = c * (9/5) + 32
                    await self.sendBasicMessage(message.frm, f"{c} Celcius is {f} Fahrenheight")
                except Exception:
                    await self.sendBasicMessage(message.frm, "Invalid command, try `c2f 32.5`")
            case "f2c":
                try:
                    f = float(command.strip().split()[1])
                    c = (5/9) * (f - 32)
                    await self.sendBasicMessage(message.frm, f"{f} Fahrenheight is {c} Celcius")
                except Exception:
                    await self.sendBasicMessage(message.frm, "Invalid command, try `c2f 32.5`")
            case _:
                await self.sendBasicMessage(message.frm, command)

    async def handle_message(self, msg_type: str, message: Message):
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
        #didcomm.message.GenericMessage.lang="en"
        message = Message(
            type="https://didcomm.org/messagepickup/3.0/status-request",
            id=str(uuid.uuid4()),
            body={},
            frm=self.my_did,
            to=[MEDIATOR_DID],
        )
        message = await self.sendMessage(message, target=MEDIATOR_DID)
        #print(message)

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
            # print(message)
            for attach in message.attachments:
                logger.info("Received message %s", attach.id[:-58])
                unpacked_msg = await unpack(
                    resolvers_config=self.resolvers_config,
                    packed_msg=attach.data.json,
                )
                msg = unpacked_msg.message
                logger.info("Received message %s", unpacked_msg.message)
                await self.handle_message(msg.type, msg)
                #print(msg.type)
                if msg.type == "https://didcomm.org/basicmessage/2.0/message":
                    logger.info(f"Got message: {msg.body['content']}")
                #return
                message = Message(
                    type="https://didcomm.org/messagepickup/3.0/messages-received",
                    id=str(uuid.uuid4()),
                    body={
                        "message_id_list": [ msg.id for msg in message.attachments ],
                    },
                    frm=self.my_did,
                    to=[MEDIATOR_DID],
                )
                message = await self.sendMessage(message, target=MEDIATOR_DID)

                return


    async def sendMessage(self, message: Message, target: DID, ws: websockets.connect | None = None):

        pack_config = didcomm.pack_encrypted.PackEncryptedConfig()
        pack_config.forward = True
        pack_result = await didcomm.pack_encrypted.pack_encrypted(
            resolvers_config=self.resolvers_config,
            message=message,
            frm=self.my_did if target == MEDIATOR_DID else self.did,
            to=target,
            pack_config=pack_config,
        )
        packed_msg = pack_result.packed_msg
        logger.debug(f"Sending {message} to {pack_result.service_metadata.service_endpoint}")
        logger.info(f"Sending a '{message.type}' message to target DID.")
        if ws:
            logger.debug("Sending via websocket %s", packed_msg)
            await ws.send(packed_msg)
            logger.debug("Sent over websocket")
            return
        post_response = requests.post(pack_result.service_metadata.service_endpoint, data=packed_msg)
        try:
            # logging.debug(json.dumps(json.loads(packed_msg), indent=2))
            post_response_json = post_response.json()
            msg_type = post_response_json.get("type")
            if msg_type and "problem-report" in msg_type:
                logger.error(post_response_json)
            logger.error(post_response_json)
            # print(json.dumps(didcomm.__dict__, indent=2, default=lambda o: '<not serializable>'))
            unpack_result = await unpack(
                resolvers_config=self.resolvers_config,
                packed_msg=post_response_json,
            )
            message = unpack_result.message
            logger.debug(message)
            return message
        except Exception as err:
            logger.exception(err)
            pass
        return

    async def sendBasicMessage(self, target_did: DID, message: str):
        message = Message(
            type="https://didcomm.org/basicmessage/2.0/message",
            body={"content": message},
            id=str(uuid.uuid4()),
            frm=self.did,
            to=[target_did],
        )
        await self.sendMessage(message, target_did)

    async def handle_websocket(self):
        async with self.websocket as websocket:
            #await websocket.send("msg")
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
            #async for message in websocket:
            while True:
                message = await websocket.recv()
                #print(message)
                logger.info("Got message over websocket")
                try:
                    unpacked_msg = await unpack(
                        resolvers_config=self.resolvers_config,
                        packed_msg=json.loads(message.decode()),
                    )
                    msg = unpacked_msg.message
                    logger.info("Received message %s", unpacked_msg.message)
                    if msg.frm != MEDIATOR_DID:
                        await self.handle_message(msg.type, msg)
                except Exception as err:
                    logger.error("Error encountered")
                    logger.exception(err)
                    pass
            await websocket.close()

    async def start(self):
        secret_manager = SecretsManager()
        secrets = secret_manager.load_secrets()
        #secrets = None
        if not secrets:
            secrets = secret_manager.generate_secrets()
            #secrets = secret_manager.generate_and_save()

        self.my_did = secrets["did"]
        print("did: ", self.my_did)
        resolved = resolve(self.my_did)
        print(json.dumps(resolved, indent=2))

        self.resolvers_config = get_resolver_config(secrets)
        target_did = "did:peer:2.Vz6Mks5aqa1RFwGSxWdY7FTpAyqPzym5hJCjDJG8UZkhUueSU.Ez6LSjz7FHdcyhpArArFr6Z1DX9cdq3sct7iQMidwKX43LAyG.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6ImRpZDpwZWVyOjIuRXo2TFNqdFBDbzFXTDhKSHppYm02aUxhSFU0NkVhaG9hajZCVkRlenVWclpYNlFaMS5WejZNa3RBU0VRSDZMNkY2OEt3UjQ1TWlNSlFNQzF2djlSb3RNcDhpd3pGQ2ZLa3NaLlNXM3NpZENJNkltUnRJaXdpY3lJNkltaDBkSEJ6T2k4dlpHVjJMbU5zYjNWa2JXVmthV0YwYjNJdWFXNWthV05wYjNSbFkyZ3VhVzh2YldWemMyRm5aU0lzSW5JaU9sdGRMQ0poSWpwYkltUnBaR052YlcwdmRqSWlMQ0prYVdSamIyMXRMMkZwY0RJN1pXNTJQWEptWXpFNUlsMTlMSHNpZENJNkltUnRJaXdpY3lJNkluZHpjem92TDNkekxtUmxkaTVqYkc5MVpHMWxaR2xoZEc5eUxtbHVaR2xqYVc5MFpXTm9MbWx2TDNkeklpd2ljaUk2VzEwc0ltRWlPbHNpWkdsa1kyOXRiUzkyTWlJc0ltUnBaR052YlcwdllXbHdNanRsYm5ZOWNtWmpNVGtpWFgxZCIsImFjY2VwdCI6WyJkaWRjb21tL3YyIl19fQ"

        #user_input = input("Target DID: ").strip()
        #try:
        #    resolve(user_input)
        #except Exception as err:
        #    raise Exception("Invalid DID specified") from err

        #target_did = user_input
        self.did = self.my_did

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
            #resolved_did = resolve(mediator_did)
            self.did = generate(
                [KeySpec.encryption(secrets["x25519"]["public"]), KeySpec.verification(secrets["ed25519"]["public"])],
                #resolved_did["services"],
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
            self.resolvers_config.secrets_resolver.add_keys_for_did(self.did)
        #message = Message(
        #    type="https://didcomm.org/coordinate-mediation/3.0/recipient-update",
        #    id=str(uuid.uuid4()),
        #    body={
        #        "updates": [
        #            {
        #                "recipient_did": did,
        #                "action": "add",
        #            },
        #        ],
        #    },
        #    frm=my_did,
        #    to=[MEDIATOR_DID],
        #)
        #message = await sendMessage(message, target=MEDIATOR_DID)
        #print(message)

        await self.fetch_messages()

        mediator_resolved = resolve(MEDIATOR_DID)
        print(mediator_resolved)
        mediator_websocket = filter(lambda x: x["serviceEndpoint"].startswith("ws"), mediator_resolved["service"])
        mediator_websocket = list(mediator_websocket)[0]
        logger.debug("Mediator Websocket Address: %s", mediator_websocket)
        if mediator_websocket:
            logger.info("Found Mediation websocket, connecting")
            self.websocket = websockets.connect(uri=mediator_websocket["serviceEndpoint"])
            self.websock_proc = asyncio.create_task(self.handle_websocket())
            await asyncio.sleep(25)



        from datetime import datetime
        display_time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        message = Message(
            type="https://didcomm.org/user-profile/1.0/profile",
            body={
                "profile": {
                    "displayName": f"Frostyfrog (script) @ {display_time}",
                    "description": "I'm a bot written in python",
                },
            },
            id=str(uuid.uuid4()),
            frm=self.did,
            to=[target_did],
        )
        #await self.sendMessage(message, target_did)

        # return

        message = Message(
            type="https://didcomm.org/question-answer/1.0/question",
            body={
                "question_text": "Alice, are you on the phone with Bob from Faber Bank right now?",
                "question_detail": "This is optional fine-print giving context to the question and its various answers.",
                "valid_responses": [
                    {"text": "Yes, it's me"},
                    {"text": "No, that's not me!"},
                ],
            },
            id=str(uuid.uuid4()),
            frm=self.did,
            to=[target_did],
        )
        await self.sendMessage(message, target_did)

        await self.sendBasicMessage(target_did, "Testing from a script!")
        await self.sendBasicMessage(target_did, "This contact is from a script written in Python 3. If you received this message, then that means that the proof of concept worked! However, one of the huge flaws at present is the over-complicated nature")
        await self.sendBasicMessage(target_did, "There are a few functions/methods being overridden in underlying libraries to bypass problems related to did:peer:2 and the libraries that implement them (primarily the didcomm library)")
        await self.sendBasicMessage(target_did, "Anyways, I hope you enjoyed this quick demo!")
        await self.sendBasicMessage(target_did, "またね〜")
        while True:
            await asyncio.sleep(5)
            if not mediator_websocket:
                await self.fetch_messages()
        # return

async def main():
    try:
        bot = Bot()
        await bot.start()
    except Exception as e:
        print("Exception?", e)
        print(traceback.format_exc())

loop = asyncio.get_event_loop()
tasks = [
    loop.create_task(main())
]
loop.run_until_complete(asyncio.wait(tasks))
loop.close()
