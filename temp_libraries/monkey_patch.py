from typing import List, Dict, Any, Union
import didcomm.pack_encrypted as pe
from did_peer_2 import ServiceEncoder
from didcomm.protocols.routing.forward import wrap_in_forward
import logging

logger = logging.getLogger(__name__)


def mock_expand_service(
    self,
    service: Union[Dict[str, Any], List[Dict[str, Any]]]
) -> Dict[str, Any]:
    """Reverse the abbreviations in a service dictionary.

    This method will perform the inverse of abbreviate_service, replacing
    abbreviations with their full string.
    """
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
                self._expand_service(e)
                if isinstance(e, dict) else e for e in v
            ]

    return service


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


def patch():
    pe.__forward_if_needed = mock__forward_if_needed
    ServiceEncoder._expand_service = mock_expand_service

