import didcomm
import pydid
from typing import Optional, List, Dict, Any
from didcomm.common.types import VerificationMethodType

from did_peer_2 import resolve


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
        doc = resolve(did)
        doc["service"] = [
            self.transform_new_to_old_service(service)
            for service in doc["service"]
        ]

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
            })
            for vm in doc["verificationMethod"]
        ]
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
        return resolved

    def transform_new_to_old_service(self, service: Dict[str, Any]) -> Dict[str, Any]:
        """Transform a new service into an old service.

        This is a bandaid for the fact that the DIDComm python library is expecting
        old style services.
        """
        if isinstance(service["serviceEndpoint"], dict):
            service_endpoint = service["serviceEndpoint"].get("uri")
            accept = service["serviceEndpoint"].get("accept")
            routing_keys = service["serviceEndpoint"].get("routingKeys")
            service["serviceEndpoint"] = service_endpoint or ""
            service["accept"] = accept or ["didcomm/v2"]
            service["routing_keys"] = routing_keys or []
            return service

        return service


class BasicSecretsResolver(didcomm.secrets.secrets_resolver.SecretsResolver):

    def __init__(self, secrets, secrets_config):
        self._secrets = secrets
        self.secrets_config = secrets_config

    async def get_key(self, kid: str) -> Optional[didcomm.secrets.secrets_resolver.Secret]:
        secret = self._secrets.get(kid)
        return secret if secret else None

    async def get_keys(self, kids: List[str]) -> List[str]:
        return [kid for kid in self._secrets.keys() if kid in kids]

    def add_keys_for_did(self, did):
        pub_key_multi = self.secrets_config["ed25519"]["public"]
        x_pub_key_multi = self.secrets_config["x25519"]["public"]
        priv_key_multi = self.secrets_config["ed25519"]["private"]
        x_priv_key_multi = self.secrets_config["x25519"]["private"]
        pub_ref = pub_key_multi[1:9]
        x_pub_ref = x_pub_key_multi[1:9]
        secret = {
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
        }
        self._secrets.update(secret)

def get_resolver_config(secrets):
        did = secrets["did"]
        pub_key_multi = secrets["ed25519"]["public"]
        x_pub_key_multi = secrets["x25519"]["public"]
        priv_key_multi = secrets["ed25519"]["private"]
        x_priv_key_multi = secrets["x25519"]["private"]
        pub_ref = pub_key_multi[1:9]
        x_pub_ref = x_pub_key_multi[1:9]
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
        }, secrets)
        dr = PeerDID2()
        return didcomm.common.resolvers.ResolversConfig(sr, dr)
