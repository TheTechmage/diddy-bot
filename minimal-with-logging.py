import asyncio
import uuid
import os
import sys
import logging
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

from didcomm_messaging import quickstart

OLD_BOT_DID = 'did:peer:2.Ez6LSg7dftRECRoeLvHx5FXG77SLL2GGHX5C2UbWbQTrQw8xb.Vz6MksRzg3RHj8PK7dJb53TgynsCDyKMQfQfG7oP5ggrAuFa1.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6ImRpZDpwZWVyOjIuVno2TWt0QVNFUUg2TDZGNjhLd1I0NU1pTUpRTUMxdnY5Um90TXA4aXd6RkNmS2tzWi5FejZMU2p0UENvMVdMOEpIemlibTZpTGFIVTQ2RWFob2FqNkJWRGV6dVZyWlg2UVoxLlNleUowSWpvaVpHMGlMQ0p6SWpwN0luVnlhU0k2SW1oMGRIQnpPaTh2WkdWMkxtTnNiM1ZrYldWa2FXRjBiM0l1YVc1a2FXTnBiM1JsWTJndWFXOHZiV1Z6YzJGblpTSXNJbUVpT2xzaVpHbGtZMjl0YlM5Mk1pSXNJbVJwWkdOdmJXMHZZV2x3TWp0bGJuWTljbVpqTVRraVhTd2ljaUk2VzExOWZRLlNleUowSWpvaVpHMGlMQ0p6SWpwN0luVnlhU0k2SW5kemN6b3ZMM2R6TG1SbGRpNWpiRzkxWkcxbFpHbGhkRzl5TG1sdVpHbGphVzkwWldOb0xtbHZMM2R6SWl3aVlTSTZXeUprYVdSamIyMXRMM1l5SWl3aVpHbGtZMjl0YlM5aGFYQXlPMlZ1ZGoxeVptTXhPU0pkTENKeUlqcGJYWDE5IiwiYSI6WyJkaWRjb21tL3YyIl19fQ'
RELAY_DID = 'did:peer:2.Vz6MktASEQH6L6F68KwR45MiMJQMC1vv9RotMp8iwzFCfKksZ.Ez6LSjtPCo1WL8JHzibm6iLaHU46Eahoaj6BVDezuVrZX6QZ1.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHBzOi8vZGV2LmNsb3VkbWVkaWF0b3IuaW5kaWNpb3RlY2guaW8vbWVzc2FnZSIsImEiOlsiZGlkY29tbS92MiIsImRpZGNvbW0vYWlwMjtlbnY9cmZjMTkiXSwiciI6W119fQ.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6IndzczovL3dzLmRldi5jbG91ZG1lZGlhdG9yLmluZGljaW90ZWNoLmlvL3dzIiwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmMxOSJdLCJyIjpbXX19'

async def main():
    did, secrets = quickstart.generate_did()
    DMP = await quickstart.setup_default(did, secrets, enable_compatibility_prefix=True)
    relayed_did = await quickstart.setup_relay(DMP, did, RELAY_DID, *secrets) or did
    logger.info("our did: %s" % did)
    logger.info("our relayed did: %s" % relayed_did)

    target_did = input("DID to message (blank for diddy-bot)> ")
    if not target_did.startswith("did:"):
        target_did = OLD_BOT_DID

    message = {
        "type": "https://didcomm.org/basicmessage/2.0/message",
        # "id": str(uuid.uuid4()),
        "body": {"content": input("Message to send> ")},
        "frm": relayed_did,
        "lang": "en",
        "to": [target_did],
    }
    await quickstart.send_http_message(DMP, relayed_did, message, target=target_did)
    await asyncio.sleep(1)
    async def print_msg(msg):
        print("Received Message: ", msg["body"])
    await quickstart.fetch_relayed_messages(DMP, did, RELAY_DID, print_msg)

loop = asyncio.get_event_loop()
tasks = [loop.create_task(main())]
loop.run_until_complete(asyncio.wait(tasks))
loop.close()
