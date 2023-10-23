import json
import uuid
import traceback
import requests
import asyncio
import didcomm
import pydid
import logging
from typing import Optional, List, Dict, Any
from didcomm.common.types import VerificationMethodType

from didcomm.protocols.routing.forward import wrap_in_forward
import didcomm.pack_encrypted as pe
from base58 import b58encode
from did_peer_2 import KeySpec, generate, resolve, ServiceEncoder
from nacl.signing import SigningKey
import sys

root = logging.getLogger()
root.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

#logging.basicConfig(level=logging.DEBUG)
logging.getLogger('didcomm').setLevel(logging.DEBUG)
print("Loggers: ", [name for name in logging.root.manager.loggerDict])
loggers = [logging.getLogger(name) for name in logging.root.manager.loggerDict]
for logger in loggers:
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)


def mock_expand_service(self, service: Dict[str, Any]) -> Dict[str, Any]:
    """Reverse the abbreviations in a service dictionary.

    This method will perform the inverse of abbreviate_service, replacing
    abbreviations with their full string.
    """
    #print("meep")
    service = service[0] if isinstance(service, list) else service
    service = {
        self.reverse_common_string_abbreviations.get(k, k): v
        for k, v in service.items()
    }
    if "type" in service:
        service["type"] = self.reverse_common_string_abbreviations.get(
            service["type"], service["type"]
        )

    for k, v in service.items():
        if isinstance(v, dict):
            service[k] = self._expand_service(v)
        if isinstance(v, list):
            service[k] = [
                self._expand_service(e) if isinstance(e, dict) else e for e in v
            ]

    return service

logger = logging.getLogger(__name__)


async def mock__forward_if_needed(
    resolvers_config,
    packed_msg,
    to,
    did_services_chain,
    pack_config,
    pack_params,
):

    if not pack_config.forward:
        logger.debug("forward is turned off")
        return None

    # build routing keys them using recipient service information
    if not did_services_chain:
        logger.debug("No service endpoint found: skipping forward wrapping")
        return None

    # last service is for 'to' DID
    routing_keys = did_services_chain[-1].routing_keys

    # if not routing_keys:
    #    return None

    # prepend routing with alternative endpoints
    # starting from the second mediator if any
    # (the first one considered to have URI endpoint)
    # cases:
    #   ==1 usual sender forward process
    #   >1 alternative endpoints
    #   >2 alternative endpoints recursion
    # TODO
    #   - case: a mediator's service has non-empty routing keys
    #     list (not covered by the spec for now)
    if len(did_services_chain) > 1:
        routing_keys = [
            s.service_endpoint for s in did_services_chain[1:]
        ] + routing_keys

    return await wrap_in_forward(
        resolvers_config=resolvers_config,
        packed_msg=packed_msg,
        to=to,
        routing_keys=routing_keys,
        enc_alg_anon=pack_config.enc_alg_anon,
        headers=pack_params.forward_headers,
        didcomm_id_generator=pack_params.forward_didcomm_id_generator,
    )
pe.__forward_if_needed = mock__forward_if_needed
#print(pe.__dict__)
#asd

ServiceEncoder._expand_service = mock_expand_service


class PeerDID2(didcomm.did_doc.did_resolver.DIDResolver):

    @staticmethod
    def method_type_str_to_enum(method_type: str) -> VerificationMethodType:
        return {
            "JsonWebKey2020": VerificationMethodType.JSON_WEB_KEY_2020,
            "Ed25519VerificationKey2018": VerificationMethodType.ED25519_VERIFICATION_KEY_2018,  # noqa
            "X25519KeyAgreementKey2019": VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2019,  # noqa
            "Ed25519VerificationKey2020": VerificationMethodType.ED25519_VERIFICATION_KEY_2020,  # noqa
            "X25519KeyAgreementKey2020": VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2020,  # noqa
        }[method_type]

    async def resolve(self, did: str) -> Optional[pydid.doc.DIDDocument]:
        #print("")
        #print(did)
        doc = resolve(did)
        doc["service"] = [
            self.transform_new_to_old_service(service)
            for service in doc["service"]
        ]
        #print(doc["service"])
        #print("===> .:.:.:.")
        #print(json.dumps(doc, indent=2))
        #print("=> .:")

        docdid = doc["id"]

        def get_key(id):
            for key in doc["verificationMethod"]:
                if key["id"] == id:
                    return docdid + "#" + key["publicKeyMultibase"][1:9]

        doc["authentication"] = [
            get_key(id) for id in doc["authentication"]
        ]
        doc["keyAgreement"] = [
            get_key(id) for id in doc["keyAgreement"]
        ]
        doc["verificationMethod"] = [
            didcomm.did_doc.did_doc.VerificationMethod(**{
                "id": docdid + "#" + vm["publicKeyMultibase"][1:9],
                "controller": vm["controller"],
                "type": self.method_type_str_to_enum(vm["type"]),
                "verification_material": didcomm.common.types.VerificationMaterial(
                    format=didcomm.common.types.VerificationMaterialFormat.MULTIBASE,
                    value=vm["publicKeyMultibase"],
                ),
                #"publicKeyMultibase": vm["publicKeyMultibase"],
            })
            for vm in doc["verificationMethod"]
        ]
        # print(json.dumps(doc, indent=2))
        #print(".:.:.:. <===")
        services = [
            didcomm.did_doc.did_doc.DIDCommService(
                id=did + service["id"],
                service_endpoint=service["serviceEndpoint"],
                routing_keys=service.get("routingKeys", []),
                accept=service.get("accept", ["didcomm/v2"]),
            )
            for service in doc["service"]
        ]
        resolved = didcomm.did_doc.did_doc.DIDDoc(**{
            "did": did,
            "key_agreement_kids": doc["keyAgreement"],
            "authentication_kids": doc["authentication"],
            "verification_methods": doc["verificationMethod"],
            "didcomm_services": services,
        })
        #print(resolved.serialize())
        #print(".=:=.")
        return resolved

    def transform_new_to_old_service(self, service: Dict[str, Any]) -> Dict[str, Any]:
        """Transform a new service into an old service.

        This is a bandaid for the fact that the DIDComm python library is expecting
        old style services.
        """
        if isinstance(service["serviceEndpoint"], dict):
            service_endpoint = service["serviceEndpoint"]["uri"]
            accept = service["serviceEndpoint"].get("accept")
            routing_keys = service["serviceEndpoint"].get("routingKeys")
            service["serviceEndpoint"] = service_endpoint
            service["accept"] = accept or ["didcomm/v2"]
            service["routing_keys"] = routing_keys or []
            return service

        return service


class BasicSecretsResolver(didcomm.secrets.secrets_resolver.SecretsResolver):

    def __init__(self, secrets):
        self._secrets = secrets

    async def get_key(self, kid: str) -> Optional[didcomm.secrets.secrets_resolver.Secret]:
        secret = self._secrets.get(kid)
        return secret if secret else None

    async def get_keys(self, kids: List[str]) -> List[str]:
        return [kid for kid in self._secrets.keys() if kid in kids]


MULTIBASE_BASE58BTC = "z"

# 1110 1101  == ed
# VarInt(ed) == 1110 1101 0000 0001
# VarInt(ed) == 0000 0001 0000 0000
MULTICODEC_ED25519_PUB = b"\xed\x01"
MULTICODEC_X25519_PUB = b"\xec\x01"
MULTICODEC_ED25519_PRIV = b"\x13\x00"
MULTICODEC_X25519_PRIV = b"\x13\x02"
MULTICODEC_ED25519_PRIV = b"\x80&" 
MULTICODEC_X25519_PRIV = b"\x82&"


class SecretsManager:

    def __init__(self, storage_file: str = None):
        self.file = storage_file or "secrets.json"

    def load_secrets(self):
        try:
            file = open(self.file, "rb")
            config = json.loads(file.read())
            return config
        except Exception:
            logger.debug("Secrets file doesn't exist")
            return None

    def store_secrets(self, secrets):
        try:
            file = open(self.file, "wb+")
            file.write(json.dumps(secrets).encode())
        except Exception as err:
            logger.debug("Failed to write secrets file")
            logger.exception(err)

    def generate_secrets(self):

        # ED25519 - For authentication
        priv_key = SigningKey.generate()
        pub_key = priv_key.verify_key

        # X25519 - For encryption
        x_priv_key = SigningKey.generate().to_curve25519_private_key()
        x_pub_key = x_priv_key.public_key


        pub_key_multi = (
            MULTIBASE_BASE58BTC + b58encode(MULTICODEC_ED25519_PUB + pub_key.encode()).decode()
        )
        x_pub_key_multi = (
            MULTIBASE_BASE58BTC + b58encode(MULTICODEC_X25519_PUB + x_pub_key.encode()).decode()
        )
        priv_key_multi = (
            MULTIBASE_BASE58BTC + b58encode(MULTICODEC_ED25519_PRIV + priv_key.encode()).decode()
        )
        x_priv_key_multi = (
            MULTIBASE_BASE58BTC + b58encode(MULTICODEC_X25519_PRIV + x_priv_key.encode()).decode()
        )

        #print(pub_key_multi, x_pub_key_multi)

        did = generate(
            [KeySpec.encryption(x_pub_key_multi), KeySpec.verification(pub_key_multi)],
            [
                {
                    "type": "DIDCommMessaging",
                    "serviceEndpoint": {
                        "uri": f"https://frostyfrog.net/api/schedule.json?run={uuid.uuid4()}",
                        "accept": ["didcomm/v2", "didcomm/aip2;env=rfc587"],
                        "routingKeys": ["did:example:123456789abcdefghi#keys-1"],
                    },
                }
            ],
        )
        secrets = {
            "ed25519": {
                "public": pub_key_multi,
                "private": priv_key_multi,
            },
            "x25519": {
                "public": x_pub_key_multi,
                "private": x_priv_key_multi,
            },
            "did": did,
        }

        return secrets

async def main():
    try:
        secret_manager = SecretsManager()
        secrets = secret_manager.load_secrets()
        if not secrets:
            secrets = secret_manager.generate_secrets()
            secret_manager.store_secrets(secrets)
        did = secrets["did"]
        pub_key_multi = secrets["ed25519"]["public"]
        x_pub_key_multi = secrets["x25519"]["public"]
        priv_key_multi = secrets["ed25519"]["private"]
        x_priv_key_multi = secrets["x25519"]["private"]
        print("did: ", did)
        #pub_ref = b58encode(MULTICODEC_ED25519_PUB + pub_key.encode()).decode()
        #x_pub_ref = b58encode(MULTICODEC_X25519_PUB + x_pub_key.encode()).decode()
        #pub_ref = "key-2"
        #x_pub_ref = "key-1"
        pub_ref = pub_key_multi[1:9]
        x_pub_ref = x_pub_key_multi[1:9]
        resolved = resolve(did)

        print(json.dumps(resolved, indent=2))
        sr = BasicSecretsResolver({
            f"{did}#{x_pub_ref}": didcomm.secrets.secrets_resolver.Secret(**{
                "type":didcomm.common.types.VerificationMethodType.ED25519_VERIFICATION_KEY_2020,
                "kid": f"{did}#{x_pub_ref}",
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

        target_did = "did:peer:2.Vz6Mkk5UnJmiSdPjvwDLrzV5avSmhVDSxcR6CZqtiX5EyhMok.Ez6LSoBGn3Xd11ziG52oeZ3KiAJtKTNgjaYdMYFnSV2kEgcgz.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6ImRpZDpwZWVyOjIuRXo2TFNqdFBDbzFXTDhKSHppYm02aUxhSFU0NkVhaG9hajZCVkRlenVWclpYNlFaMS5WejZNa3RBU0VRSDZMNkY2OEt3UjQ1TWlNSlFNQzF2djlSb3RNcDhpd3pGQ2ZLa3NaLlNXM3NpZENJNkltUnRJaXdpY3lJNkltaDBkSEJ6T2k4dlpHVjJMbU5zYjNWa2JXVmthV0YwYjNJdWFXNWthV05wYjNSbFkyZ3VhVzh2YldWemMyRm5aU0lzSW5JaU9sdGRMQ0poSWpwYkltUnBaR052YlcwdmRqSWlMQ0prYVdSamIyMXRMMkZwY0RJN1pXNTJQWEptWXpFNUlsMTlMSHNpZENJNkltUnRJaXdpY3lJNkluZHpjem92TDNkekxtUmxkaTVqYkc5MVpHMWxaR2xoZEc5eUxtbHVaR2xqYVc5MFpXTm9MbWx2TDNkeklpd2ljaUk2VzEwc0ltRWlPbHNpWkdsa1kyOXRiUzkyTWlJc0ltUnBaR052YlcwdllXbHdNanRsYm5ZOWNtWmpNVGtpWFgxZCIsImFjY2VwdCI6WyJkaWRjb21tL3YyIl19fQ"
        #target_did = "did:peer:2.Ez6LSjtPCo1WL8JHzibm6iLaHU46Eahoaj6BVDezuVrZX6QZ1.Vz6MktASEQH6L6F68KwR45MiMJQMC1vv9RotMp8iwzFCfKksZ.SW3sidCI6ImRtIiwicyI6Imh0dHBzOi8vZGV2LmNsb3VkbWVkaWF0b3IuaW5kaWNpb3RlY2guaW8vbWVzc2FnZSIsInIiOltdLCJhIjpbImRpZGNvbW0vdjIiLCJkaWRjb21tL2FpcDI7ZW52PXJmYzE5Il19LHsidCI6ImRtIiwicyI6IndzczovL3dzLmRldi5jbG91ZG1lZGlhdG9yLmluZGljaW90ZWNoLmlvL3dzIiwiciI6W10sImEiOlsiZGlkY29tbS92MiIsImRpZGNvbW0vYWlwMjtlbnY9cmZjMTkiXX1d#6LSjtPCo"

        #target_did = "did:peer:2.Vz6Mkk5UnJmiSdPjvwDLrzV5avSmhVDSxcR6CZqtiX5EyhMok.Ez6LSoBGn3Xd11ziG52oeZ3KiAJtKTNgjaYdMYFnSV2kEgcgz.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6ImRpZDpwZWVyOjIuRXo2TFNqdFBDbzFXTDhKSHppYm02aUxhSFU0NkVhaG9hajZCVkRlenVWclpYNlFaMS5WejZNa3RBU0VRSDZMNkY2OEt3UjQ1TWlNSlFNQzF2djlSb3RNcDhpd3pGQ2ZLa3NaLlNleUowSWpvaVpHMGlMQ0p6SWpwYkltaDBkSEJ6T2k4dlpHVjJMbU5zYjNWa2JXVmthV0YwYjNJdWFXNWthV05wYjNSbFkyZ3VhVzh2YldWemMyRm5aU0lzSW5kemN6b3ZMM2R6TG1SbGRpNWpiRzkxWkcxbFpHbGhkRzl5TG1sdVpHbGphVzkwWldOb0xtbHZMM2R6SWwwc0luSWlPbHRkTENKaElqcGJJbVJwWkdOdmJXMHZkaklpTENKa2FXUmpiMjF0TDJGcGNESTdaVzUyUFhKbVl6RTVJbDE5IiwiYWNjZXB0IjpbImRpZGNvbW0vdjIiXX0sInIiOltdfQ"

        #target_did = "did:peer:2.Vz6Mkk5UnJmiSdPjvwDLrzV5avSmhVDSxcR6CZqtiX5EyhMok.Ez6LSoBGn3Xd11ziG52oeZ3KiAJtKTNgjaYdMYFnSV2kEgcgz.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6ImRpZDpwZWVyOjIuRXo2TFNqdFBDbzFXTDhKSHppYm02aUxhSFU0NkVhaG9hajZCVkRlenVWclpYNlFaMS5WejZNa3RBU0VRSDZMNkY2OEt3UjQ1TWlNSlFNQzF2djlSb3RNcDhpd3pGQ2ZLa3NaLlNleUowSWpvaVpHMGlMQ0p6SWpwYkltaDBkSEJ6T2k4dlpHVjJMbU5zYjNWa2JXVmthV0YwYjNJdWFXNWthV05wYjNSbFkyZ3VhVzh2YldWemMyRm5aU0pkTENKeUlqcGJYU3dpWVNJNld5SmthV1JqYjIxdEwzWXlJaXdpWkdsa1kyOXRiUzloYVhBeU8yVnVkajF5Wm1NeE9TSmRmUSIsImFjY2VwdCI6WyJkaWRjb21tL3YyIl19LCJyIjpbXX0"

        #target_did = "did:peer:2.Vz6Mkk5UnJmiSdPjvwDLrzV5avSmhVDSxcR6CZqtiX5EyhMok.Ez6LSoBGn3Xd11ziG52oeZ3KiAJtKTNgjaYdMYFnSV2kEgcgz.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6ImRpZDpwZWVyOjIuRXo2TFNqdFBDbzFXTDhKSHppYm02aUxhSFU0NkVhaG9hajZCVkRlenVWclpYNlFaMS5WejZNa3RBU0VRSDZMNkY2OEt3UjQ1TWlNSlFNQzF2djlSb3RNcDhpd3pGQ2ZLa3NaLlNleUowSWpvaVpHMGlMQ0p6SWpwYkltaDBkSEJ6T2k4dlpHVjJMbU5zYjNWa2JXVmthV0YwYjNJdWFXNWthV05wYjNSbFkyZ3VhVzh2YldWemMyRm5aU0pkTENKeUlqcGJJbVJwWkRwd1pXVnlPakl1UlhvMlRGTnFkRkJEYnpGWFREaEtTSHBwWW0wMmFVeGhTRlUwTmtWaGFHOWhhalpDVmtSbGVuVldjbHBZTmxGYU1TNVdlalpOYTNSQlUwVlJTRFpNTmtZMk9FdDNValExVFdsTlNsRk5RekYyZGpsU2IzUk5jRGhwZDNwR1EyWkxhM05hTGxOWE0zTnBaRU5KTmtsdFVuUkphWGRwWTNsSk5rbHRhREJrU0VKNlQyazRkbHBIVmpKTWJVNXpZak5XYTJKWFZtdGhWMFl3WWpOSmRXRlhOV3RoVjA1d1lqTlNiRmt5WjNWaFZ6aDJZbGRXZW1NeVJtNWFVMGx6U1c1SmFVOXNkR1JNUTBwb1NXcHdZa2x0VW5CYVIwNTJZbGN3ZG1ScVNXbE1RMHByWVZkU2FtSXlNWFJNTWtad1kwUkpOMXBYTlRKUVdFcHRXWHBGTlVsc01UbE1TSE5wWkVOSk5rbHRVblJKYVhkcFkzbEpOa2x1WkhwamVtOTJURE5rZWt4dFVteGthVFZxWWtjNU1WcEhNV3hhUjJ4b1pFYzVlVXh0YkhWYVIyeHFZVmM1TUZwWFRtOU1iV3gyVEROa2VrbHBkMmxqYVVrMlZ6RXdjMGx0UldsUGJITnBXa2RzYTFreU9YUmlVemt5VFdsSmMwbHRVbkJhUjA1MllsY3dkbGxYYkhkTmFuUnNZbTVaT1dOdFdtcE5WR3RwV0ZneFpDSmRMQ0poSWpwYkltUnBaR052YlcwdmRqSWlMQ0prYVdSamIyMXRMMkZwY0RJN1pXNTJQWEptWXpFNUlsMTkiLCJhY2NlcHQiOlsiZGlkY29tbS92MiJdfSwiciI6W119"

        target_did = "did:peer:2.Vz6Mkk5UnJmiSdPjvwDLrzV5avSmhVDSxcR6CZqtiX5EyhMok.Ez6LSoBGn3Xd11ziG52oeZ3KiAJtKTNgjaYdMYFnSV2kEgcgz.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6ImRpZDpwZWVyOjIuRXo2TFNqdFBDbzFXTDhKSHppYm02aUxhSFU0NkVhaG9hajZCVkRlenVWclpYNlFaMS5WejZNa3RBU0VRSDZMNkY2OEt3UjQ1TWlNSlFNQzF2djlSb3RNcDhpd3pGQ2ZLa3NaLlNXM3NpZENJNkltUnRJaXdpY3lJNkltaDBkSEJ6T2k4dlpHVjJMbU5zYjNWa2JXVmthV0YwYjNJdWFXNWthV05wYjNSbFkyZ3VhVzh2YldWemMyRm5aU0lzSW5JaU9sdGRMQ0poSWpwYkltUnBaR052YlcwdmRqSWlMQ0prYVdSamIyMXRMMkZwY0RJN1pXNTJQWEptWXpFNUlsMTlMSHNpZENJNkltUnRJaXdpY3lJNkluZHpjem92TDNkekxtUmxkaTVqYkc5MVpHMWxaR2xoZEc5eUxtbHVaR2xqYVc5MFpXTm9MbWx2TDNkeklpd2ljaUk2VzEwc0ltRWlPbHNpWkdsa1kyOXRiUzkyTWlJc0ltUnBaR052YlcwdllXbHdNanRsYm5ZOWNtWmpNVGtpWFgxZCIsImFjY2VwdCI6WyJkaWRjb21tL3YyIl19fQ"

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
            #print("--------------------")
            #print(message)
            #print("--------------------")

            pack_config = didcomm.pack_encrypted.PackEncryptedConfig()
            pack_config.forward = True
            #print("")
            #print(pack_config)
            #print("")
            pack_result = await didcomm.pack_encrypted.pack_encrypted(
                resolvers_config=didcomm.common.resolvers.ResolversConfig(sr, dr),
                message=message,
                frm=did,
                to=target_did,
                pack_config=pack_config,
            )
            packed_msg = pack_result.packed_msg
            #print("")
            #print(f"Sending {packed_msg} to {pack_result.service_metadata.service_endpoint}")
            post_response = requests.post(pack_result.service_metadata.service_endpoint, data=packed_msg)
            ##post_response_json = post_response.json()
            #print("====")
            #print(json.dumps(json.loads(packed_msg), indent=2))
            #print("====")
            ##print(post_response_json)
            #print("====")

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
        #print(sys.exc_info()[2])

loop = asyncio.get_event_loop()
tasks = [
    loop.create_task(main())
]
loop.run_until_complete(asyncio.wait(tasks))
loop.close()
