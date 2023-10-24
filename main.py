import json
import uuid
import os
import traceback
import requests
import asyncio
import didcomm
import logging

from did_peer_2 import resolve
import sys

from temp_libraries import monkey_patch
from temp_libraries.resolvers import BasicSecretsResolver, PeerDID2
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


async def main():
    try:
        secret_manager = SecretsManager()
        secrets = secret_manager.load_secrets()
        if not secrets:
            secrets = secret_manager.generate_and_save()
        did = secrets["did"]
        pub_key_multi = secrets["ed25519"]["public"]
        x_pub_key_multi = secrets["x25519"]["public"]
        priv_key_multi = secrets["ed25519"]["private"]
        x_priv_key_multi = secrets["x25519"]["private"]
        print("did: ", did)
        pub_ref = pub_key_multi[1:9]
        x_pub_ref = x_pub_key_multi[1:9]
        resolved = resolve(did)

        print(json.dumps(resolved, indent=2))
        sr = BasicSecretsResolver({
            f"{did}#{pub_ref}": didcomm.secrets.secrets_resolver.Secret(**{
                "type":didcomm.common.types.VerificationMethodType.ED25519_VERIFICATION_KEY_2020,
                "kid": f"{did}#{pub_ref}",
                "verification_material": didcomm.common.types.VerificationMaterial(
                    format=didcomm.common.types.VerificationMaterialFormat.MULTIBASE,
                    value=priv_key_multi,
                ),
            }),
            f"{did}#{x_pub_ref}": didcomm.secrets.secrets_resolver.Secret(**{
                "type":didcomm.common.types.VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2020,
                "kid": f"{did}#{x_pub_ref}",
                "verification_material": didcomm.common.types.VerificationMaterial(
                    format=didcomm.common.types.VerificationMaterialFormat.MULTIBASE,
                    value=x_priv_key_multi,
                ),
            }),
        })
        dr = PeerDID2()

        target_did = "did:peer:2.Vz6Mkh6Vii9dzFQ9FnUisinCr1prMn9U7CpvsFT6NzujAf9JM.Ez6LSmJNE7mhQpXcVMQR4yRPaxVH18GoMKsri4RmzXJZG71YG.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6ImRpZDpwZWVyOjIuRXo2TFNqdFBDbzFXTDhKSHppYm02aUxhSFU0NkVhaG9hajZCVkRlenVWclpYNlFaMS5WejZNa3RBU0VRSDZMNkY2OEt3UjQ1TWlNSlFNQzF2djlSb3RNcDhpd3pGQ2ZLa3NaLlNXM3NpZENJNkltUnRJaXdpY3lJNkltaDBkSEJ6T2k4dlpHVjJMbU5zYjNWa2JXVmthV0YwYjNJdWFXNWthV05wYjNSbFkyZ3VhVzh2YldWemMyRm5aU0lzSW5JaU9sdGRMQ0poSWpwYkltUnBaR052YlcwdmRqSWlMQ0prYVdSamIyMXRMMkZwY0RJN1pXNTJQWEptWXpFNUlsMTlMSHNpZENJNkltUnRJaXdpY3lJNkluZHpjem92TDNkekxtUmxkaTVqYkc5MVpHMWxaR2xoZEc5eUxtbHVaR2xqYVc5MFpXTm9MbWx2TDNkeklpd2ljaUk2VzEwc0ltRWlPbHNpWkdsa1kyOXRiUzkyTWlJc0ltUnBaR052YlcwdllXbHdNanRsYm5ZOWNtWmpNVGtpWFgxZCIsImFjY2VwdCI6WyJkaWRjb21tL3YyIl19fQ"

        user_input = input("Target DID: ").strip()
        can_resolve = False
        try:
            resolve(user_input)
            can_resolve = True
        except:
            pass
        if can_resolve:
            target_did = user_input

        async def sendMessage(message):

            pack_config = didcomm.pack_encrypted.PackEncryptedConfig()
            pack_config.forward = True
            pack_result = await didcomm.pack_encrypted.pack_encrypted(
                resolvers_config=didcomm.common.resolvers.ResolversConfig(sr, dr),
                message=message,
                frm=did,
                to=target_did,
                pack_config=pack_config,
            )
            packed_msg = pack_result.packed_msg
            logger.debug(f"Sending {packed_msg} to {pack_result.service_metadata.service_endpoint}")
            logger.info(f"Sending a '{message.type}' message to target DID.")
            post_response = requests.post(pack_result.service_metadata.service_endpoint, data=packed_msg)
            ##post_response_json = post_response.json()
            #print(json.dumps(json.loads(packed_msg), indent=2))
            ##print(post_response_json)

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
        await sendMessage(message)
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
        await sendMessage(message)

        async def sendBasicMessage(message: str):
            message = didcomm.message.Message(
                type="https://didcomm.org/basicmessage/2.0/message",
                body={"content": message},
                id=str(uuid.uuid4()),
                frm=did,
                to=[target_did],
            )
            await sendMessage(message)
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
