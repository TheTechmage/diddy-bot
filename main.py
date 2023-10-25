import json
import uuid
import os
import traceback
import requests
import asyncio
import didcomm
from typing import Dict
import logging
import base64

from did_peer_2 import resolve
from did_peer_2 import KeySpec, generate
import sys

from temp_libraries import monkey_patch
from temp_libraries.resolvers import BasicSecretsResolver, PeerDID2, get_resolver_config
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


async def main():
    try:
        secret_manager = SecretsManager()
        secrets = secret_manager.load_secrets()
        if not secrets:
            secrets = secret_manager.generate_and_save()

        my_did = secrets["did"]
        print("did: ", my_did)
        resolved = resolve(my_did)
        print(json.dumps(resolved, indent=2))

        resolvers_config = get_resolver_config(secrets)
        target_did = "did:peer:2.Vz6Mkh6Vii9dzFQ9FnUisinCr1prMn9U7CpvsFT6NzujAf9JM.Ez6LSmJNE7mhQpXcVMQR4yRPaxVH18GoMKsri4RmzXJZG71YG.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6ImRpZDpwZWVyOjIuRXo2TFNqdFBDbzFXTDhKSHppYm02aUxhSFU0NkVhaG9hajZCVkRlenVWclpYNlFaMS5WejZNa3RBU0VRSDZMNkY2OEt3UjQ1TWlNSlFNQzF2djlSb3RNcDhpd3pGQ2ZLa3NaLlNXM3NpZENJNkltUnRJaXdpY3lJNkltaDBkSEJ6T2k4dlpHVjJMbU5zYjNWa2JXVmthV0YwYjNJdWFXNWthV05wYjNSbFkyZ3VhVzh2YldWemMyRm5aU0lzSW5JaU9sdGRMQ0poSWpwYkltUnBaR052YlcwdmRqSWlMQ0prYVdSamIyMXRMMkZwY0RJN1pXNTJQWEptWXpFNUlsMTlMSHNpZENJNkltUnRJaXdpY3lJNkluZHpjem92TDNkekxtUmxkaTVqYkc5MVpHMWxaR2xoZEc5eUxtbHVaR2xqYVc5MFpXTm9MbWx2TDNkeklpd2ljaUk2VzEwc0ltRWlPbHNpWkdsa1kyOXRiUzkyTWlJc0ltUnBaR052YlcwdllXbHdNanRsYm5ZOWNtWmpNVGtpWFgxZCIsImFjY2VwdCI6WyJkaWRjb21tL3YyIl19fQ"

        user_input = input("Target DID: ").strip()
        try:
            resolve(user_input)
        except Exception as err:
            raise Exception("Invalid DID specified") from err

        target_did = user_input
        did = my_did

        async def sendMessage(message, target):

            pack_config = didcomm.pack_encrypted.PackEncryptedConfig()
            pack_config.forward = True
            pack_result = await didcomm.pack_encrypted.pack_encrypted(
                resolvers_config=resolvers_config,
                message=message,
                frm=my_did if target == MEDIATOR_DID else did,
                to=target,
                pack_config=pack_config,
            )
            packed_msg = pack_result.packed_msg
            logger.debug(f"Sending {packed_msg} to {pack_result.service_metadata.service_endpoint}")
            logger.info(f"Sending a '{message.type}' message to target DID.")
            post_response = requests.post(pack_result.service_metadata.service_endpoint, data=packed_msg)
            try:
                # logging.debug(json.dumps(json.loads(packed_msg), indent=2))
                post_response_json = post_response.json()
                msg_type = post_response_json.get("type")
                if msg_type and "problem-report" in msg_type:
                    logger.error(post_response_json)
                # print(json.dumps(didcomm.__dict__, indent=2, default=lambda o: '<not serializable>'))
                unpack_result = await unpack(
                    resolvers_config=resolvers_config,
                    packed_msg=post_response_json,
                )
                message = unpack_result.message
                logger.debug(message)
                return message
            except Exception as err:
                logger.exception(err)
                pass
            return

        message = didcomm.message.Message(
            type="https://didcomm.org/coordinate-mediation/3.0/mediate-request",
            id=str(uuid.uuid4()),
            body={},
            frm=my_did,
            to=[MEDIATOR_DID],
        )
        message = await sendMessage(message, target=MEDIATOR_DID)

        if message.type == "https://didcomm.org/coordinate-mediation/3.0/mediate-grant":
            mediator_did = message.body["routing_did"][0]
            #resolved_did = resolve(mediator_did)
            did = generate(
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
            print("mediated did: ", did)
            resolvers_config.secrets_resolver.add_keys_for_did(did)
        #message = didcomm.message.Message(
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

        #didcomm.message.GenericMessage.lang="en"
        message = didcomm.message.Message(
            type="https://didcomm.org/messagepickup/3.0/status-request",
            id=str(uuid.uuid4()),
            body={},
            frm=my_did,
            to=[MEDIATOR_DID],
        )
        message = await sendMessage(message, target=MEDIATOR_DID)
        #print(message)

        if message.body["message_count"] > 0:
            message = didcomm.message.Message(
                type="https://didcomm.org/messagepickup/3.0/delivery-request",
                id=str(uuid.uuid4()),
                body={
                    "limit": message.body["message_count"],
                },
                frm=my_did,
                to=[MEDIATOR_DID],
            )
            message = await sendMessage(message, target=MEDIATOR_DID)
            # print(message)
            for attach in message.attachments:
                logger.info("Received message %s", attach.id[:-58])
                unpacked_msg = await unpack(
                    resolvers_config=resolvers_config,
                    packed_msg=attach.data.json,
                )
                msg = unpacked_msg.message
                logger.info("Received message %s", unpacked_msg.message)
                #print(msg.type)
                if msg.type == "https://didcomm.org/basicmessage/2.0/message":
                    print(f"Got message: {msg.body['content']}")
            #return
            message = didcomm.message.Message(
                type="https://didcomm.org/messagepickup/3.0/messages-received",
                id=str(uuid.uuid4()),
                body={
                    "message_id_list": [ msg.id for msg in message.attachments ],
                },
                frm=my_did,
                to=[MEDIATOR_DID],
            )
            message = await sendMessage(message, target=MEDIATOR_DID)

            return


        from datetime import datetime
        display_time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        message = didcomm.message.Message(
            type="https://didcomm.org/user-profile/1.0/profile",
            body={
                "profile": {
                    "displayName": f"Frostyfrog (script) @ {display_time}",
                    "description": "I'm a bot written in python",
                },
            },
            id=str(uuid.uuid4()),
            frm=did,
            to=[target_did],
        )
        await sendMessage(message, target_did)

        # return

        message = didcomm.message.Message(
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
            frm=did,
            to=[target_did],
        )
        await sendMessage(message, target_did)

        async def sendBasicMessage(message: str):
            message = didcomm.message.Message(
                type="https://didcomm.org/basicmessage/2.0/message",
                body={"content": message},
                id=str(uuid.uuid4()),
                frm=did,
                to=[target_did],
            )
            await sendMessage(message, target_did)
        await sendBasicMessage("Testing from a script!")
        await sendBasicMessage("This contact is from a script written in Python 3. If you received this message, then that means that the proof of concept worked! However, one of the huge flaws at present is the over-complicated nature")
        await sendBasicMessage("There are a few functions/methods being overridden in underlying libraries to bypass problems related to did:peer:2 and the libraries that implement them (primarily the didcomm library)")
        await sendBasicMessage("Anyways, I hope you enjoyed this quick demo!")
        await sendBasicMessage("またね〜")
    except Exception as e:
        print("Exception?", e)
        print(traceback.format_exc())

loop = asyncio.get_event_loop()
tasks = [
    loop.create_task(main())
]
loop.run_until_complete(asyncio.wait(tasks))
loop.close()
