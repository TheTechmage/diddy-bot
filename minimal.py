import asyncio
import uuid
import os, sys

import bootstrap
from bootstrap import Message
#__package__ = "didcomm_book_demo.minimal"

OLD_BOT_DID = 'did:peer:2.Ez6LSg7dftRECRoeLvHx5FXG77SLL2GGHX5C2UbWbQTrQw8xb.Vz6MksRzg3RHj8PK7dJb53TgynsCDyKMQfQfG7oP5ggrAuFa1.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6ImRpZDpwZWVyOjIuVno2TWt0QVNFUUg2TDZGNjhLd1I0NU1pTUpRTUMxdnY5Um90TXA4aXd6RkNmS2tzWi5FejZMU2p0UENvMVdMOEpIemlibTZpTGFIVTQ2RWFob2FqNkJWRGV6dVZyWlg2UVoxLlNleUowSWpvaVpHMGlMQ0p6SWpwN0luVnlhU0k2SW1oMGRIQnpPaTh2WkdWMkxtTnNiM1ZrYldWa2FXRjBiM0l1YVc1a2FXTnBiM1JsWTJndWFXOHZiV1Z6YzJGblpTSXNJbUVpT2xzaVpHbGtZMjl0YlM5Mk1pSXNJbVJwWkdOdmJXMHZZV2x3TWp0bGJuWTljbVpqTVRraVhTd2ljaUk2VzExOWZRLlNleUowSWpvaVpHMGlMQ0p6SWpwN0luVnlhU0k2SW5kemN6b3ZMM2R6TG1SbGRpNWpiRzkxWkcxbFpHbGhkRzl5TG1sdVpHbGphVzkwWldOb0xtbHZMM2R6SWl3aVlTSTZXeUprYVdSamIyMXRMM1l5SWl3aVpHbGtZMjl0YlM5aGFYQXlPMlZ1ZGoxeVptTXhPU0pkTENKeUlqcGJYWDE5IiwiYSI6WyJkaWRjb21tL3YyIl19fQ'

async def main():
    did, secrets = bootstrap.generate_did()
    DMP = await bootstrap.setup_default(did, secrets)

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
    print(await bootstrap.send_http_message(DMP, did, message, target=target_did))
    await asyncio.sleep(1)
    # We have no way of fetching messages, since we did not establish mediation.
    # await self.fetch_messages()

loop = asyncio.get_event_loop()
tasks = [loop.create_task(main())]
loop.run_until_complete(asyncio.wait(tasks))
loop.close()
