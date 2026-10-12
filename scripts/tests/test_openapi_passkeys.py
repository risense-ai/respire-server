"""Validate the canonical browser transport contract, not parser-acceptance parity.

Compatibility-only null wrappers, unused known response keys and legacy binary
representations can be tolerated by runtime deserialization but are deliberately
excluded from the supported client schemas. No runtime behavior is changed.

The Rust signed-authenticator tests cover cryptographic verification separately.
Only the OpenAPI 3.0 `nullable` keyword and local schema-reference locations are
translated here; validation is performed by jsonschema rather than a custom
validator. No network references or real credentials are used.
"""

import base64
import copy
from pathlib import Path
import unittest

from jsonschema import Draft7Validator, FormatChecker
import yaml


ROOT = Path(__file__).resolve().parents[2]
DOCUMENT = yaml.safe_load((ROOT / "service/openapi.yaml").read_text())
SCHEMAS = DOCUMENT["components"]["schemas"]
PREFIX = "#/components/schemas/"
ENDPOINT_SCHEMAS = {
    "/api/self/passkeys/register/finish": "PasskeyRegistrationFinish",
    "/api/self/passkeys/register/test": "PasskeyAssertionFinish",
    "/api/self/passkeys/register/commit": "PasskeyRegistrationCommit",
    "/api/self/passkeys/unlock/finish": "PasskeyAssertionFinish",
}
REGISTRATION = "/api/self/passkeys/register/finish"
COMMIT = "/api/self/passkeys/register/commit"
ASSERTIONS = tuple(path for path in ENDPOINT_SCHEMAS if path != REGISTRATION)


def json_schema(value):
    if isinstance(value, list):
        return [json_schema(item) for item in value]
    if not isinstance(value, dict):
        return value
    result = {key: json_schema(item) for key, item in value.items() if key != "nullable"}
    if "$ref" in result:
        reference = result["$ref"]
        if not reference.startswith(PREFIX) or reference[len(PREFIX):] not in SCHEMAS:
            raise ValueError(f"Unexpected or missing schema reference: {reference}")
        result["$ref"] = "#/definitions/" + reference[len(PREFIX):]
    if value.get("nullable"):
        if not isinstance(result.get("type"), str):
            raise ValueError("OpenAPI nullable conversion requires an explicit scalar type")
        result["type"] = [result["type"], "null"]
    return result


def encoded(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def request_for(path):
    response = {"clientDataJSON": encoded(b"synthetic-client-data")}
    if path == REGISTRATION:
        response.update(attestationObject=encoded(b"synthetic-attestation"), transports=["internal"])
        extensions = {"prf": {"enabled": True}, "credProps": {"rk": True}}
    else:
        response.update(
            authenticatorData=encoded(b"synthetic-authenticator-data"),
            signature=encoded(b"synthetic-signature"),
            userHandle=None,
        )
        extensions = {"prf": {"enabled": True}}
    value = {
        "ceremony_id": "11111111-1111-4111-8111-111111111111",
        "credential": {
            "id": encoded(bytes(range(32))),
            "rawId": encoded(bytes(range(32))),
            "type": "public-key",
            "response": response,
            "clientExtensionResults": extensions,
        },
    }
    if path == COMMIT:
        value["wrapper"] = {
            "version": 1,
            "kdf": "webauthn-prf-hkdf-sha256-v1",
            "wrapped_urk": encoded(bytes(48)),
            "nonce": encoded(bytes(12)),
        }
    return value


class PasskeyOpenApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validators = {}
        definitions = json_schema(SCHEMAS)
        for path in ENDPOINT_SCHEMAS:
            request_schema = DOCUMENT["paths"][path]["post"]["requestBody"]["content"]["application/json"]["schema"]
            schema = {"definitions": definitions, **json_schema(request_schema)}
            Draft7Validator.check_schema(schema)
            cls.validators[path] = Draft7Validator(schema, format_checker=FormatChecker())

    def assert_valid(self, path, value):
        self.assertEqual(list(self.validators[path].iter_errors(value)), [], path)

    def assert_invalid(self, path, value):
        self.assertTrue(list(self.validators[path].iter_errors(value)), path)

    def test_schema_definitions_are_valid_and_endpoint_references_are_phase_specific(self):
        for name, schema in SCHEMAS.items():
            with self.subTest(schema=name):
                Draft7Validator.check_schema(json_schema(schema))
        for path, expected in ENDPOINT_SCHEMAS.items():
            schema = DOCUMENT["paths"][path]["post"]["requestBody"]["content"]["application/json"]["schema"]
            self.assertEqual(schema, {"$ref": PREFIX + expected})
            self.assertIs(SCHEMAS[expected]["additionalProperties"], False)
            self.assert_valid(path, request_for(path))

    def test_registration_accepts_optional_public_capability_hints(self):
        for extensions in [None, {}, {"prf": {}}, {"prf": {"enabled": False}},
                           {"credProps": {}}, {"credProps": {"rk": True}},
                           {"credProps": {"rk": False}}]:
            with self.subTest(extensions=extensions):
                value = request_for(REGISTRATION)
                if extensions is None:
                    del value["credential"]["clientExtensionResults"]
                else:
                    value["credential"]["clientExtensionResults"] = extensions
                self.assert_valid(REGISTRATION, value)
        for transports in [None, [], ["usb", "hybrid", "future-transport"]]:
            value = request_for(REGISTRATION)
            value["credential"]["response"]["transports"] = transports
            self.assert_valid(REGISTRATION, value)

    def test_assertions_accept_missing_null_or_account_sized_user_handle(self):
        for path in ASSERTIONS:
            for handle in [None, encoded(bytes(16))]:
                value = request_for(path)
                value["credential"]["response"]["userHandle"] = handle
                self.assert_valid(path, value)
            value = request_for(path)
            del value["credential"]["response"]["userHandle"]
            del value["credential"]["clientExtensionResults"]
            self.assert_valid(path, value)

    def test_unknown_properties_are_rejected_at_every_public_object_boundary(self):
        for path in ENDPOINT_SCHEMAS:
            for location in [(), ("credential",), ("credential", "response"),
                             ("credential", "clientExtensionResults"),
                             ("credential", "clientExtensionResults", "prf")]:
                with self.subTest(path=path, location=location):
                    value = request_for(path)
                    target = value
                    for field in location:
                        target = target[field]
                    target["unexpected"] = "forbidden"
                    self.assert_invalid(path, value)
        value = request_for(REGISTRATION)
        value["credential"]["clientExtensionResults"]["credProps"]["unexpected"] = True
        self.assert_invalid(REGISTRATION, value)

    def test_prf_output_and_unknown_extensions_are_rejected(self):
        for path in ENDPOINT_SCHEMAS:
            for extra in [{"results": {"first": encoded(bytes(32))}},
                          {"first": encoded(bytes(32))}, {"second": encoded(bytes(32))}]:
                value = request_for(path)
                value["credential"]["clientExtensionResults"]["prf"].update(extra)
                self.assert_invalid(path, value)
            for unknown in ["uvm", "credProtect", "largeBlob", "extensions"]:
                value = request_for(path)
                value["credential"]["clientExtensionResults"][unknown] = {}
                self.assert_invalid(path, value)

    def test_capability_objects_and_boolean_hints_have_strict_types(self):
        for path in ENDPOINT_SCHEMAS:
            for invalid in [None, [], True, "true", 1]:
                value = request_for(path)
                value["credential"]["clientExtensionResults"] = invalid
                self.assert_invalid(path, value)
                value = request_for(path)
                value["credential"]["clientExtensionResults"]["prf"] = invalid
                self.assert_invalid(path, value)
            for invalid in [None, [], {}, "true", 1]:
                value = request_for(path)
                value["credential"]["clientExtensionResults"]["prf"]["enabled"] = invalid
                self.assert_invalid(path, value)
        for invalid in [None, [], True, "true", 1, {"rk": None}, {"rk": "true"}, {"rk": 1}]:
            value = request_for(REGISTRATION)
            value["credential"]["clientExtensionResults"]["credProps"] = invalid
            self.assert_invalid(REGISTRATION, value)

    def test_assertions_reject_registration_only_properties(self):
        for path in ASSERTIONS:
            for props in [{}, {"rk": True}, {"rk": False}]:
                value = request_for(path)
                value["credential"]["clientExtensionResults"]["credProps"] = props
                self.assert_invalid(path, value)

    def test_required_request_credential_and_response_fields(self):
        for path in ENDPOINT_SCHEMAS:
            for field in ["ceremony_id", "credential"]:
                value = request_for(path)
                del value[field]
                self.assert_invalid(path, value)
            for field in ["id", "rawId", "type", "response"]:
                value = request_for(path)
                del value["credential"][field]
                self.assert_invalid(path, value)
            required = (["clientDataJSON", "attestationObject"] if path == REGISTRATION
                        else ["clientDataJSON", "authenticatorData", "signature"])
            for field in required:
                value = request_for(path)
                del value["credential"]["response"][field]
                self.assert_invalid(path, value)

    def test_registration_and_assertion_response_shapes_are_not_interchangeable(self):
        registration = request_for(REGISTRATION)["credential"]["response"]
        assertion = request_for(COMMIT)["credential"]["response"]
        for path in ENDPOINT_SCHEMAS:
            value = request_for(path)
            value["credential"]["response"] = copy.deepcopy(assertion if path == REGISTRATION else registration)
            self.assert_invalid(path, value)

    def test_credentials_have_typed_bounded_binary_fields(self):
        for path in ENDPOINT_SCHEMAS:
            for field in ["id", "rawId"]:
                for invalid in [None, 1, [], {}, "", "A", "A" * 1367, "AA==", "a/b+"]:
                    value = request_for(path)
                    value["credential"][field] = invalid
                    self.assert_invalid(path, value)
            for invalid in ["password", "PUBLIC-KEY", None, 1]:
                value = request_for(path)
                value["credential"]["type"] = invalid
                self.assert_invalid(path, value)
            for field in ["clientDataJSON", "attestationObject" if path == REGISTRATION else "signature"]:
                for invalid in [None, 1, [], {}, "", "AA==", "a/b+", "A" * 131073]:
                    value = request_for(path)
                    value["credential"]["response"][field] = invalid
                    self.assert_invalid(path, value)

    def test_invalid_handles_transports_and_ceremony_ids_are_rejected(self):
        for path in ASSERTIONS:
            for handle in [False, {}, "", encoded(bytes(15)), encoded(bytes(17)), "A" * 21 + "="]:
                value = request_for(path)
                value["credential"]["response"]["userHandle"] = handle
                self.assert_invalid(path, value)
        for transports in [True, {}, "internal", [1], [None]]:
            value = request_for(REGISTRATION)
            value["credential"]["response"]["transports"] = transports
            self.assert_invalid(REGISTRATION, value)
        for path in ENDPOINT_SCHEMAS:
            value = request_for(path)
            value["ceremony_id"] = "not-a-uuid"
            self.assert_invalid(path, value)

    def test_canonical_requests_omit_tolerated_legacy_parser_fields(self):
        for path in ENDPOINT_SCHEMAS:
            value = request_for(path)
            unused = "signature" if path == REGISTRATION else "attestationObject"
            value["credential"]["response"][unused] = encoded(b"unused-compatibility-field")
            self.assert_invalid(path, value)
            if path != COMMIT:
                value = request_for(path)
                value["wrapper"] = None
                self.assert_invalid(path, value)
            value = request_for(path)
            binary = "attestationObject" if path == REGISTRATION else "signature"
            value["credential"]["response"][binary] = [1, 2, 3]
            self.assert_invalid(path, value)

    def test_commit_requires_exact_opaque_wrapper_and_other_phases_disallow_it(self):
        value = request_for(COMMIT)
        del value["wrapper"]
        self.assert_invalid(COMMIT, value)
        for field in ["version", "kdf", "wrapped_urk", "nonce"]:
            value = request_for(COMMIT)
            del value["wrapper"][field]
            self.assert_invalid(COMMIT, value)
        for field, bad in [("version", 2), ("kdf", "unknown"), ("wrapped_urk", encoded(bytes(32))),
                           ("nonce", encoded(bytes(16))), ("urk", "plaintext"), ("prf_output", "secret")]:
            value = request_for(COMMIT)
            value["wrapper"][field] = bad
            self.assert_invalid(COMMIT, value)
        for path in ENDPOINT_SCHEMAS:
            if path != COMMIT:
                value = request_for(path)
                value["wrapper"] = request_for(COMMIT)["wrapper"]
                self.assert_invalid(path, value)


if __name__ == "__main__":
    unittest.main()
