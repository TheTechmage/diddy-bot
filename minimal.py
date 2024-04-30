import asyncio
from didcomm_messaging import quickstart

RELAY_DID = 'did:web:dev.cloudmediator.indiciotech.io'

async def main():
    did, secrets = quickstart.generate_did()

    # Setup the didcomm-messaging-python library object
    DMP = await quickstart.setup_default(did, secrets)

    # Connect to RELAY_DID as our inbound relay/mediator
    relayed_did = await quickstart.setup_relay(DMP, did, RELAY_DID, *secrets) or did
    print("our did: %s" % did)
    print("our relayed did: %s" % relayed_did)

    # Get a did from the user to send a message to
    target_did = input("DID to message (blank for diddy-bot)> ")
    if not await DMP.resolver.is_resolvable(target_did):
        raise Exception("Invalid did specified: {}".format(target_did))

    # Send a message to target_did from the user
    message = {
        "type": "https://didcomm.org/basicmessage/2.0/message",
        # "id": str(uuid.uuid4()),
        "body": {"content": input("Message to send> ")},
        "from": relayed_did,
        "lang": "en",
        "to": [target_did],
    }
    await quickstart.send_http_message(DMP, relayed_did, message, target=target_did)

    # This is out handler function that is called each time we receive a message
    async def print_msg(msg):
        print("Received Message: ", msg["type"], msg["body"])

    # Fetch messages manually
    await asyncio.sleep(1)
    await quickstart.fetch_relayed_messages(DMP, did, RELAY_DID, print_msg)

    # Have messages streamed to us via the relay/mediator's websocket
    await quickstart.websocket_loop(DMP, did, RELAY_DID, print_msg)

asyncio.run(main())
