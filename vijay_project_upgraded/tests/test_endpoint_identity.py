"""Tests for EndpointIdentity abstraction."""

from trojan_defense.core.models.identity import EndpointIdentity


class TestEndpointIdentity:
    def test_deterministic_resolution(self):
        id1 = EndpointIdentity.resolve()
        id2 = EndpointIdentity.resolve()

        assert id1.endpoint_id == id2.endpoint_id
        assert id1.hostname == id2.hostname
        assert id1.platform == id2.platform
        assert len(id1.endpoint_id) > 0

    def test_override_resolution(self):
        custom_id = "custom-node-999"
        custom_host = "isolated-sec-lab"
        resolved = EndpointIdentity.resolve(
            endpoint_id_override=custom_id,
            hostname_override=custom_host,
            agent_version="1.2.3",
        )

        assert resolved.endpoint_id == custom_id
        assert resolved.hostname == custom_host
        assert resolved.agent_version == "1.2.3"

    def test_dict_serialization_roundtrip(self):
        identity = EndpointIdentity.resolve()
        as_dict = identity.to_dict()
        reconstructed = EndpointIdentity.from_dict(as_dict)

        assert reconstructed.endpoint_id == identity.endpoint_id
        assert reconstructed.hostname == identity.hostname
        assert reconstructed.platform == identity.platform
        assert reconstructed.architecture == identity.architecture
        assert reconstructed.agent_version == identity.agent_version
