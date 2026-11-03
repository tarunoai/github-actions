# /// script
# requires-python = ">=3.12"
# dependencies = ["cryptography"]
#
# [tool.uv]
# no-build = true
# exclude-newer = "P7D"
# ///
"""Sign macOS executables with the selected PKCS#11 backend.

The input contains one directory per target, each holding its executables.
The new output directory preserves this layout and includes the signing
certificate in each target directory.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from enum import Enum
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes


class SigningComponent(Enum):
    """The components needed to sign macOS executables."""

    RCODESIGN = "RCODESIGN"
    PKCS11 = "PKCS11"

    def path(self, directory: Path) -> Path:
        """Return the component's local path in the download directory."""
        match self:
            case SigningComponent.RCODESIGN:
                return directory / "rcodesign"
            case SigningComponent.PKCS11:
                return directory / "libakv_pkcs11.so"

    def is_executable(self) -> bool:
        """Return whether the downloaded component needs executable permissions."""
        match self:
            case SigningComponent.RCODESIGN:
                return True
            case SigningComponent.PKCS11:
                return False


def run_azure_command(command: list[str | Path], description: str) -> None:
    """Run an Azure download without logging private account or vault details."""
    try:
        subprocess.run(
            command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except subprocess.CalledProcessError:
        raise RuntimeError(f"{description} failed") from None


def verify_sha256(path: Path, expected: str) -> None:
    """Require a downloaded file to match its configured SHA-256 digest."""
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected.lower():
        raise ValueError(f"SHA-256 mismatch: {path.name}")


def download_signing_component(component: SigningComponent, directory: Path) -> Path:
    """Download a pinned signing component and return its ready-to-use path."""
    path = component.path(directory)
    run_azure_command(
        [
            "az",
            "storage",
            "blob",
            "download",
            "--auth-mode",
            "login",
            "--only-show-errors",
            "--account-name",
            os.environ["STORAGE_ACCOUNT"],
            "--container-name",
            os.environ["STORAGE_CONTAINER"],
            "--name",
            os.environ[f"COMPONENT_{component.value}_BLOB"],
            "--file",
            path,
        ],
        f"Downloading {path.name}",
    )
    verify_sha256(path, os.environ[f"COMPONENT_{component.value}_SHA256"])
    if component.is_executable():
        path.chmod(0o755)
    return path


def certificate_sha256(path: Path) -> str:
    """Return the SHA-256 fingerprint of a PEM certificate's DER encoding."""
    certificate = x509.load_pem_x509_certificate(path.read_bytes())
    return certificate.fingerprint(hashes.SHA256()).hex()


def sign_binaries(
    unsigned: Path | None, signed: Path | None, *, preflight: bool = False
) -> None:
    """Download the pinned components and certificate once, then sign every target."""
    backend = os.environ.get("SIGNING_BACKEND", "azure")
    if backend not in ("azure", "signer-service"):
        raise ValueError(f"Unsupported signing backend: {backend}")
    if preflight and backend != "signer-service":
        raise ValueError("Signing preflight requires the signer-service backend")
    if not preflight and (unsigned is None or signed is None):
        raise ValueError("Signing requires unsigned and signed directories")

    required = (
        "STORAGE_ACCOUNT",
        "STORAGE_CONTAINER",
        "COMPONENT_RCODESIGN_BLOB",
        "COMPONENT_RCODESIGN_SHA256",
        "COMPONENT_PKCS11_BLOB",
        "COMPONENT_PKCS11_SHA256",
        "AZURE_KEYVAULT_NAME",
        "AZURE_KEYVAULT_KEY_VERSION",
        "KEY_NAME",
        "CERTIFICATE_SHA256",
    )
    if backend == "signer-service":
        required += (
            "SIGNER_SERVICE_ENDPOINT",
            "SIGNER_SERVICE_PURPOSE",
            "SIGNER_SERVICE_KEY_ID",
        )
    for name in required:
        if not os.environ.get(name):
            raise ValueError(f"Missing signing configuration: {name}")

    entitlements = os.environ.get("ENTITLEMENTS_FILE", "")
    entitled_binaries = set(json.loads(os.environ.get("ENTITLEMENTS_BINARIES", "[]")))
    if bool(entitlements) != bool(entitled_binaries):
        raise ValueError("Provide both an entitlements file and its executable paths")

    with tempfile.TemporaryDirectory() as temporary:
        components = Path(temporary)
        certificate = components / "certificate.pem"

        rcodesign = download_signing_component(SigningComponent.RCODESIGN, components)
        pkcs11 = download_signing_component(SigningComponent.PKCS11, components)

        run_azure_command(
            [
                "az",
                "keyvault",
                "certificate",
                "download",
                "--only-show-errors",
                "--vault-name",
                os.environ["AZURE_KEYVAULT_NAME"],
                "--name",
                os.environ["KEY_NAME"],
                "--version",
                os.environ["AZURE_KEYVAULT_KEY_VERSION"],
                "--encoding",
                "PEM",
                "--file",
                certificate,
            ],
            "Downloading the public signing certificate",
        )
        if certificate_sha256(certificate) != os.environ["CERTIFICATE_SHA256"].lower():
            raise ValueError("Signing certificate SHA-256 mismatch")

        signing_env = {**os.environ, "AKV_PKCS11_BACKEND": backend}
        if backend == "signer-service":
            signing_env.update(
                SIGNER_SERVICE_KEY_LABEL=os.environ["KEY_NAME"],
                SIGNER_SERVICE_CERTIFICATE_FILE=str(certificate),
            )

        if preflight:
            print(
                "Signing components and public certificate passed SHA-256 checks.",
                flush=True,
            )
            subprocess.run([rcodesign, "--version"], check=True, timeout=30)
            subprocess.run(
                [
                    sys.executable,
                    Path(__file__).with_name("preflight-pkcs11.py"),
                    pkcs11,
                    certificate,
                ],
                check=True,
                env=signing_env,
                timeout=90,
            )
            print(
                "Signing preflight passed; no binaries signed or output directory created."
            )
            return

        assert unsigned is not None and signed is not None
        signed.mkdir()
        for target in sorted(unsigned.iterdir()):
            destination = signed / target.name
            destination.mkdir()
            shutil.copyfile(certificate, destination / "certificate.pem")
            sources = {
                source.relative_to(target).as_posix(): source
                for source in target.rglob("*")
                if source.is_file()
            }
            if not entitled_binaries <= sources.keys():
                raise ValueError(f"Missing entitled executables in {target.name}")
            for relative, source in sorted(sources.items()):
                output = destination / relative
                output.parent.mkdir(parents=True, exist_ok=True)
                options = (
                    ["--entitlements-xml-file", entitlements]
                    if relative in entitled_binaries
                    else []
                )
                try:
                    subprocess.run(
                        [
                            rcodesign,
                            "sign",
                            "--config-file",
                            "/dev/null",
                            "--pkcs11-library",
                            pkcs11,
                            "--pkcs11-certificate-file",
                            certificate,
                            "--pkcs11-key-label",
                            os.environ["KEY_NAME"],
                            "--binary-identifier",
                            f"sh.astral.{source.name}",
                            "--code-signature-flags",
                            "runtime",
                            "--arm64-16k-code-pages",
                            *options,
                            source,
                            output,
                        ],
                        check=True,
                        env=signing_env,
                    )
                except subprocess.CalledProcessError:
                    raise RuntimeError(
                        f"Signing {target.name}/{relative} failed"
                    ) from None


def main() -> None:
    """Sign using the selected backend and settings from the protected release job."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("unsigned", type=Path, nargs="?")
    parser.add_argument("signed", type=Path, nargs="?")
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="Download and verify components, then discover the signer key without signing.",
    )
    args = parser.parse_args()

    try:
        mode = os.environ.get("PREFLIGHT_ONLY", "false")
        if mode not in ("true", "false"):
            raise ValueError("PREFLIGHT_ONLY must be true or false")
        sign_binaries(
            args.unsigned, args.signed, preflight=args.preflight or mode == "true"
        )
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
