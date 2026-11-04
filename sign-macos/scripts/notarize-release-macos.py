# /// script
# requires-python = ">=3.12"
# dependencies = ["astral-dev-toolchain-grpcurl==1.9.4", "boto3"]
#
# [tool.uv]
# no-build = true
# ///
"""Submit signed macOS executables to Apple's notarization service.

Apple scans software for malware and signing issues. On acceptance, it publishes
tickets that Gatekeeper can retrieve online when users run the binaries.
Standalone executables cannot have tickets stapled to them, so these releases
rely on that online lookup even when distributed in wheels or archives.

This script uploads all signed macOS targets and waits for Apple's result.
It authenticates to the Notary API using Azure Key Vault by default, or an
explicitly configured signer-service key, without exporting the private key.
"""

import argparse
import base64
import hashlib
import http.client
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Self
from urllib.parse import parse_qsl, urlencode, urlsplit
from zipfile import ZIP_DEFLATED, ZipFile

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

NOTARY_URL = "https://appstoreconnect.apple.com/notary/v2/submissions"
SIGNER_ALGORITHM = "SIGNING_ALGORITHM_ECDSA_P256_SHA256"


class SignerOrigin(str):
    """An HTTPS signer-service origin on port 443."""

    def __new__(cls, value: str) -> Self:
        """Validate the signer origin and normalize its authority."""
        endpoint = urlsplit(value)
        if endpoint.scheme != "https" or not endpoint.hostname:
            raise ValueError("Notarization requires a signer-service HTTPS endpoint")
        host = endpoint.hostname
        return super().__new__(
            cls, f"https://[{host}]" if ":" in host else f"https://{host}"
        )


@dataclass(frozen=True, kw_only=True)
class Signer:
    """Signer-service configuration pinned to an exact Apple metadata key version."""

    endpoint: SignerOrigin
    purpose: str
    key_id: str
    # Independently configured SHA-256 of DER SubjectPublicKeyInfo, as hex.
    spki_sha256: str
    metadata_key_version: str

    @classmethod
    def from_environment(cls) -> "Signer":
        """Load the signer endpoint, key pins, and Azure metadata version."""
        return cls(
            endpoint=SignerOrigin(os.environ["SIGNER_SERVICE_ENDPOINT"]),
            purpose=os.environ["NOTARIZATION_SIGNER_SERVICE_PURPOSE"],
            key_id=os.environ["NOTARIZATION_SIGNER_SERVICE_KEY_ID"],
            spki_sha256=os.environ["NOTARIZATION_SIGNER_SERVICE_SPKI_SHA256"].lower(),
            metadata_key_version=os.environ[
                "APPLE_NOTARIZATION_AKV_KEY_VERSION"
            ].lower(),
        )

    def metadata_url(self, vault: str, name: str) -> str:
        """Return the configured Azure metadata key URL."""
        return (
            f"https://{vault}.vault.azure.net/keys/{name}/{self.metadata_key_version}"
        )

    def validate_public_key(self, token: str) -> None:
        """Verify that signer-service advertises the pinned ES256 public key."""
        keys = self.rpc("GetPublicKeys", {"purpose": self.purpose}, token).get(
            "publicKeys", []
        )
        matches = [key for key in keys if key.get("keyId") == self.key_id]
        if len(matches) != 1 or matches[0].get("algorithm") != SIGNER_ALGORITHM:
            raise ValueError(
                "Signer did not return the pinned notarization key and algorithm"
            )
        if (
            hashlib.sha256(
                base64.b64decode(matches[0]["spkiDer"], validate=True)
            ).hexdigest()
            != self.spki_sha256
        ):
            raise ValueError("Notarization public key differs from the independent pin")

    def sign_digest(self, digest: bytes) -> bytes:
        """Sign a SHA-256 digest with the pinned ES256 key and return JOSE bytes."""
        token = oidc_token(self.endpoint)
        self.validate_public_key(token)
        result = self.rpc(
            "Sign",
            {
                "purpose": self.purpose,
                "digest": base64.b64encode(digest).decode("ascii"),
            },
            token,
        )
        if (
            result.get("keyId") != self.key_id
            or result.get("algorithm") != SIGNER_ALGORITHM
        ):
            raise ValueError(
                "Signer returned a different notarization key or algorithm"
            )
        signature = base64.b64decode(result["signature"], validate=True)
        if len(signature) != 64:
            raise ValueError("ES256 signature must contain 64 JOSE R || S bytes")
        return signature

    def rpc(self, method: str, body: dict, token: str) -> dict:
        """Call a signer-service RPC and return its decoded JSON response."""
        try:
            result = subprocess.run(
                [
                    "grpcurl",
                    "-import-path",
                    str(Path(__file__).parent / "notary_signer"),
                    "-proto",
                    "service.proto",
                    "-max-time",
                    "30",
                    # Expand the token in grpcurl so it never appears in command arguments.
                    "-expand-headers",
                    "-rpc-header",
                    "authorization: Bearer ${NOTARIZATION_OIDC_TOKEN}",
                    "-d",
                    "@",
                    f"{self.endpoint.removeprefix('https://')}:443",
                    f"oaiproto.security.signer.v1.SignerService/{method}",
                ],
                input=json.dumps(body),
                capture_output=True,
                text=True,
                check=True,
                timeout=35,
                env={**os.environ, "NOTARIZATION_OIDC_TOKEN": token},
            )
        except (OSError, subprocess.SubprocessError):
            # grpcurl errors can contain authorization headers; do not expose them.
            raise RuntimeError(f"Signer-service {method} request failed") from None
        return json.loads(result.stdout)


def oidc_token(audience: str) -> str:
    """Request a GitHub Actions OIDC token for the signer-service audience."""
    url = urlsplit(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"])
    credential = os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]
    if url.scheme != "https":
        raise ValueError("GitHub OIDC requires HTTPS")
    query = [(key, value) for key, value in parse_qsl(url.query) if key != "audience"]
    query.append(("audience", audience))
    connection = http.client.HTTPSConnection(url.hostname, port=url.port, timeout=15)
    try:
        # http.client does not follow redirects with the GitHub credential.
        connection.request(
            "GET",
            f"{url.path}?{urlencode(query)}",
            headers={"Authorization": f"Bearer {credential}"},
        )
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError(f"GitHub OIDC request returned HTTP {response.status}")
        return json.load(response)["value"]
    except (OSError, http.client.HTTPException):
        # Transport errors may include credentials; validation errors above stay specific.
        raise RuntimeError("GitHub OIDC request failed") from None
    finally:
        connection.close()


@dataclass(frozen=True, kw_only=True)
class NotarizationKey:
    """Apple account metadata and the selected remote signing backend."""

    # Versioned Azure Key Vault URL used for signing. Azure CLI authenticates
    # requests using the workflow's existing Azure login.
    url: str
    # App Store Connect identifiers used in the JWT header and claims.
    key_id: str
    issuer: str
    # When set, signer-service signs JWTs; Azure still supplies Apple account metadata.
    signer: Signer | None = None


def base64url(value: bytes) -> str:
    """Encode a JWT component without padding."""
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def azure_json(*arguments: str) -> dict:
    """Run an Azure CLI request without printing key-vault details to CI logs."""
    try:
        result = subprocess.run(
            ["az", *arguments, "--output", "json", "--only-show-errors"],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError:
        raise RuntimeError("Azure Key Vault request failed") from None
    return json.loads(result.stdout)


def notarization_key() -> NotarizationKey:
    """Resolve Apple metadata, pinned to an exact version for signer-service."""
    vault = os.environ["AZURE_KEYVAULT_NAME"]
    name = os.environ["APPLE_NOTARIZATION_AKV_KEY_NAME"]
    backend = os.environ.get("APPLE_NOTARIZATION_BACKEND", "azure")
    if backend not in {"azure", "signer-service"}:
        raise ValueError("Invalid notarization backend")
    signer = Signer.from_environment() if backend == "signer-service" else None
    key = azure_json(
        "keyvault",
        "key",
        "show",
        "--vault-name",
        vault,
        "--name",
        name,
        *(("--version", signer.metadata_key_version) if signer else ()),
        "--query",
        '{url:key.kid,key_id:tags."apple-key-id",issuer:tags."apple-issuer-id"}',
    )
    if signer and key["url"] != signer.metadata_url(vault, name):
        raise ValueError("Azure returned a different notarization metadata key version")
    if signer and not all(
        isinstance(key[field], str) and key[field] for field in ("key_id", "issuer")
    ):
        raise ValueError("Azure returned incomplete Apple notarization metadata")
    return NotarizationKey(
        url=key["url"], key_id=key["key_id"], issuer=key["issuer"], signer=signer
    )


def apple_token(key: NotarizationKey) -> str:
    """Sign a short-lived Notary API token without exporting the Apple private key."""
    now = int(time.time())
    header = {"alg": "ES256", "kid": key.key_id, "typ": "JWT"}
    claims = {
        "iss": key.issuer,
        "iat": now,
        "exp": now + 15 * 60,
        "aud": "appstoreconnect-v1",
        "scope": ["/notary/v2"],
    }
    signing_input = ".".join(
        base64url(json.dumps(value, separators=(",", ":")).encode())
        for value in (header, claims)
    )
    if key.signer:
        signature = key.signer.sign_digest(
            hashlib.sha256(signing_input.encode("ascii")).digest()
        )
        return f"{signing_input}.{base64url(signature)}"
    signature = azure_json(
        "rest",
        "--method",
        "post",
        "--url",
        f"{key.url}/sign?api-version=7.4",
        "--resource",
        "https://vault.azure.net",
        "--headers",
        "Content-Type=application/json",
        "--body",
        json.dumps(
            {
                "alg": "ES256",
                "value": base64url(
                    hashlib.sha256(signing_input.encode("ascii")).digest()
                ),
            }
        ),
    )
    if signature["kid"] != key.url:
        raise ValueError("Azure signed with an unexpected notarization key")
    if len(base64.urlsafe_b64decode(signature["value"] + "==")) != 64:
        raise ValueError("Azure returned an invalid ES256 signature")
    return f"{signing_input}.{signature['value']}"


def apple_json(token: str, suffix: str = "", body: dict | None = None) -> dict:
    """Send a JSON request to Apple's notary service."""
    request = urllib.request.Request(
        NOTARY_URL + suffix,
        data=json.dumps(body).encode() if body is not None else None,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST" if body is not None else "GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"Apple Notary API returned HTTP {error.code}") from None


def notarize(signed: Path) -> None:
    """Submit all targets' signed binaries together and wait for Apple's acceptance."""
    key = notarization_key()
    with tempfile.TemporaryDirectory(dir=os.environ.get("RUNNER_TEMP")) as temporary:
        # Apple requires a supported container: ZIP, disk image, or signed flat
        # installer package. This ZIP is only for submission; distribution uses
        # the wheels and release archives assembled later.
        # https://developer.apple.com/documentation/security/customizing-the-notarization-workflow
        archive = Path(temporary) / "notarization.zip"
        with ZipFile(archive, "w", compression=ZIP_DEFLATED) as output:
            for target in sorted(signed.iterdir()):
                for path in sorted(target.rglob("*")):
                    if not path.is_file() or path == target / "certificate.pem":
                        continue
                    path.chmod(0o755)
                    output.write(path, path.relative_to(signed))

        # Include upload time in the budget so polling uses an unexpired token.
        deadline = time.monotonic() + 600
        token = apple_token(key)
        submission = apple_json(
            token,
            body={
                "submissionName": archive.name,
                "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            },
        )["data"]
        submission_id = submission["id"]
        upload = submission["attributes"]
        print(f"Uploading Apple notarization submission {submission_id}", flush=True)
        s3 = boto3.client(
            "s3",
            aws_access_key_id=upload["awsAccessKeyId"],
            aws_secret_access_key=upload["awsSecretAccessKey"],
            aws_session_token=upload["awsSessionToken"],
            config=Config(s3={"use_accelerate_endpoint": True}),
        )
        try:
            s3.upload_file(str(archive), upload["bucket"], upload["object"])
        except (BotoCoreError, ClientError):
            raise RuntimeError("Apple notarization upload failed") from None

        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError(f"Apple notarization timed out: {submission_id}")
            status = apple_json(token, f"/{submission_id}")["data"]["attributes"][
                "status"
            ]
            if status != "In Progress":
                log_url = apple_json(token, f"/{submission_id}/logs")["data"][
                    "attributes"
                ]["developerLogUrl"]
                if not log_url.startswith("https://"):
                    raise ValueError("Apple returned an invalid notarization log URL")
                with urllib.request.urlopen(log_url, timeout=60) as response:
                    log = json.load(response)
                for issue in log.get("issues") or []:
                    print(
                        f"Apple notarization {issue['severity']}: "
                        f"{issue['path']}: {issue['message']}",
                        file=sys.stderr,
                    )
                if status != "Accepted":
                    raise ValueError(f"Apple notarization {status}: {submission_id}")
                print(f"Apple notarization accepted: {submission_id}")
                return
            time.sleep(10)


def preflight() -> None:
    """Check pinned metadata and signer access without signing or contacting Apple."""
    if os.environ.get("APPLE_NOTARIZATION_BACKEND", "azure") != "signer-service":
        raise ValueError("Notarization preflight requires signer-service backend")
    key = notarization_key()
    if key.signer is None:
        raise ValueError("Notarization preflight requires signer-service backend")
    key.signer.validate_public_key(oidc_token(key.signer.endpoint))
    print(
        "Notarization preflight passed: exact Azure metadata version and "
        "signer-service public key verified; no signing or Apple submission performed."
    )


def main() -> None:
    """Notarize the signed executables from the protected release job."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("signed", type=Path, nargs="?")
    parser.add_argument(
        "--preflight",
        action="store_true",
        help=(
            "Verify exact Azure metadata and signer-service OIDC/public-key access "
            "without signing, creating a ZIP, or contacting Apple; also enabled by "
            "PREFLIGHT_ONLY=true (signed directory not required)"
        ),
    )
    args = parser.parse_args()
    try:
        preflight_only = os.environ.get("PREFLIGHT_ONLY", "false")
        if preflight_only not in {"true", "false"}:
            raise ValueError("PREFLIGHT_ONLY must be true or false")
        if args.preflight or preflight_only == "true":
            preflight()
            return
        if args.signed is None:
            parser.error("signed is required unless preflight is enabled")
        notarize(args.signed)
    except (
        KeyError,
        OSError,
        TypeError,
        ValueError,
        RuntimeError,
        TimeoutError,
    ) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
