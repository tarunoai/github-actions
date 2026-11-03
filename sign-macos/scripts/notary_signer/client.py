"""Sign Apple JWT digests using grpcurl, GitHub OIDC, and independent key pins."""

import base64
import hashlib
import http.client
import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit

ALGORITHM = "SIGNING_ALGORITHM_ECDSA_P256_SHA256"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def backend() -> str:
    value = os.environ.get("APPLE_NOTARIZATION_BACKEND", "azure")
    require(value in {"azure", "signer-service"}, "Invalid notarization backend")
    return value


@dataclass(frozen=True, kw_only=True)
class Signer:
    """Explicit Astral configuration; never derive pins from the signer response."""

    hostname: str
    purpose: str
    key_id: str
    spki_sha256: str
    metadata_key_version: str

    @classmethod
    def from_environment(cls) -> "Signer":
        endpoint = urlsplit(os.environ.get("SIGNER_SERVICE_ENDPOINT", ""))
        require(
            endpoint.scheme == "https"
            and bool(endpoint.hostname)
            and endpoint.username is None
            and endpoint.password is None
            and endpoint.port in (None, 443)
            and endpoint.path in ("", "/")
            and not endpoint.query
            and not endpoint.fragment,
            "Notarization requires a signer-service HTTPS origin",
        )
        values = {}
        for name in ("PURPOSE", "KEY_ID", "SPKI_SHA256"):
            value = os.environ.get(f"NOTARIZATION_SIGNER_SERVICE_{name}", "")
            require(
                bool(value) and not any(c.isspace() for c in value),
                f"Missing or invalid notarization signer-service {name.lower()}",
            )
            values[name] = value
        spki = values["SPKI_SHA256"].lower()
        version = os.environ.get("APPLE_NOTARIZATION_AKV_KEY_VERSION", "").lower()
        require(
            bool(re.fullmatch(r"[0-9a-f]{64}", spki)),
            "Notarization requires an independent SPKI SHA-256 pin",
        )
        require(
            bool(re.fullmatch(r"[0-9a-f]{32}", version)),
            "Notarization requires an exact Azure metadata key version",
        )
        return cls(
            hostname=endpoint.hostname,
            purpose=values["PURPOSE"],
            key_id=values["KEY_ID"],
            spki_sha256=spki,
            metadata_key_version=version,
        )

    def metadata_url(self, vault: str, name: str) -> str:
        require(
            bool(re.fullmatch(r"[A-Za-z0-9-]+", vault))
            and bool(re.fullmatch(r"[A-Za-z0-9-]+", name)),
            "Invalid Azure notarization metadata key",
        )
        return (
            f"https://{vault}.vault.azure.net/keys/{name}/{self.metadata_key_version}"
        )

    def preflight(self) -> None:
        """Authenticate and verify the pinned public key without signing anything."""
        token = oidc_token(f"https://{self.hostname}")
        self.validate_public_key(token)

    def validate_public_key(self, token: str) -> None:
        """Require the exact independently pinned key and signing algorithm."""
        keys = self.rpc("GetPublicKeys", {"purpose": self.purpose}, token).get(
            "publicKeys"
        )
        require(isinstance(keys, list), "Invalid signer-service public keys")
        matches = [
            key
            for key in keys
            if isinstance(key, dict) and key.get("keyId") == self.key_id
        ]
        require(
            len(matches) == 1 and matches[0].get("algorithm") == ALGORITHM,
            "Signer did not return the pinned notarization key and algorithm",
        )
        require(
            hashlib.sha256(decode_bytes(matches[0].get("spkiDer"))).hexdigest()
            == self.spki_sha256,
            "Notarization public key differs from the independent pin",
        )

    def sign_digest(self, digest: bytes) -> bytes:
        require(len(digest) == 32, "Notarization requires one SHA-256 digest")
        token = oidc_token(f"https://{self.hostname}")
        self.validate_public_key(token)
        result = self.rpc(
            "Sign",
            {
                "purpose": self.purpose,
                "digest": base64.b64encode(digest).decode("ascii"),
            },
            token,
        )
        require(
            result.get("keyId") == self.key_id and result.get("algorithm") == ALGORITHM,
            "Signer returned a different notarization key or algorithm",
        )
        signature = decode_bytes(result.get("signature"))
        require(
            len(signature) == 64, "ES256 signature must contain 64 JOSE R || S bytes"
        )
        return signature

    def rpc(self, method: str, body: dict, token: str) -> dict:
        """Keep bearer tokens out of argv and redact grpcurl failures."""
        try:
            result = subprocess.run(
                [
                    "grpcurl",
                    "-import-path",
                    str(Path(__file__).parent),
                    "-proto",
                    "service.proto",
                    "-max-time",
                    "30",
                    "-expand-headers",
                    "-rpc-header",
                    "authorization: Bearer ${NOTARIZATION_OIDC_TOKEN}",
                    "-d",
                    "@",
                    f"{self.hostname}:443",
                    f"oaiproto.security.signer.v1.SignerService/{method}",
                ],
                input=json.dumps(body),
                capture_output=True,
                text=True,
                check=True,
                timeout=35,
                env={**os.environ, "NOTARIZATION_OIDC_TOKEN": token},
            )
            response = json.loads(result.stdout)
        except (OSError, subprocess.SubprocessError, ValueError):
            raise ValueError(f"Signer-service {method} request failed") from None
        require(isinstance(response, dict), "Invalid signer-service response")
        return response


def oidc_token(audience: str) -> str:
    """Use GitHub's HTTPS endpoint without following redirects with credentials."""
    url = urlsplit(os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", ""))
    credential = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
    require(
        bool(credential)
        and url.scheme == "https"
        and bool(url.hostname)
        and url.hostname.endswith(".actions.githubusercontent.com")
        and url.username is None
        and url.password is None
        and url.port in (None, 443)
        and not url.fragment,
        "A GitHub Actions HTTPS OIDC endpoint and credential are required",
    )
    query = [(key, value) for key, value in parse_qsl(url.query) if key != "audience"]
    query.append(("audience", audience))
    connection = http.client.HTTPSConnection(url.hostname, timeout=15)
    try:
        connection.request(
            "GET",
            f"{url.path}?{urlencode(query)}",
            headers={"Authorization": f"Bearer {credential}"},
        )
        response = connection.getresponse()
        require(response.status == 200, "GitHub OIDC request failed")
        body = response.read(65537)
        require(len(body) <= 65536, "GitHub OIDC response is oversized")
        data = json.loads(body)
        token = data.get("value") if isinstance(data, dict) else None
        require(
            isinstance(token, str)
            and bool(token)
            and not any(c.isspace() for c in token),
            "Invalid GitHub OIDC token",
        )
        return token
    except (OSError, http.client.HTTPException, ValueError):
        raise ValueError("GitHub OIDC request failed") from None
    finally:
        connection.close()


def decode_bytes(value: object) -> bytes:
    require(isinstance(value, str), "Invalid signer-service bytes")
    try:
        return base64.b64decode(value, validate=True)
    except ValueError:
        raise ValueError("Invalid signer-service base64") from None
