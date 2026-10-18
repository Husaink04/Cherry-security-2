#!/usr/bin/env python3
"""Create a private, IP-scoped CA and server certificate for the M1 agent ingress."""

import argparse
import ipaddress
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys


def run(*arguments: str, input_bytes: bytes | None = None) -> bytes:
    completed = subprocess.run(
        ["openssl", *arguments], input=input_bytes, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=True,
    )
    return completed.stdout


def prepare(address: str, directory: Path) -> None:
    ip = ipaddress.ip_address(address)
    if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_link_local:
        raise ValueError("an explicit private IPv4 NAT address is required")
    if not directory.is_absolute() or directory.exists() or directory.is_symlink():
        raise ValueError("certificate output must be a new absolute directory")
    parent = directory.parent
    if not parent.is_dir() or parent.resolve(strict=True) != parent or not stat.S_ISDIR(parent.lstat().st_mode):
        raise ValueError("certificate parent must be an existing non-symlink directory")
    os.umask(0o077)
    directory.mkdir(mode=0o700)
    ca_key, ca_cert = directory / "ca.key", directory / "ca.crt"
    server_key, server_cert = directory / "server.key", directory / "server.crt"
    run("genpkey", "-algorithm", "Ed25519", "-out", str(ca_key))
    run("req", "-new", "-x509", "-key", str(ca_key), "-out", str(ca_cert),
        "-days", "365", "-subj", "/CN=CherrySecurity Local Agent CA",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    run("genpkey", "-algorithm", "Ed25519", "-out", str(server_key))
    request = run("req", "-new", "-key", str(server_key),
                  "-subj", "/CN=CherrySecurity Agent Ingress",
                  "-addext", f"subjectAltName=IP:{ip}",
                  "-addext", "basicConstraints=critical,CA:FALSE",
                  "-addext", "keyUsage=critical,digitalSignature",
                  "-addext", "extendedKeyUsage=serverAuth")
    run("x509", "-req", "-in", "/dev/stdin", "-CA", str(ca_cert),
        "-CAkey", str(ca_key), "-set_serial", str(secrets.randbits(128)),
        "-days", "30", "-copy_extensions", "copy", "-out", str(server_cert),
        input_bytes=request)
    run("verify", "-CAfile", str(ca_cert), "-verify_ip", str(ip), str(server_cert))
    run("x509", "-in", str(server_cert), "-noout", "-checkend", "0")
    if run("pkey", "-in", str(server_key), "-pubout") != run("x509", "-in", str(server_cert), "-pubkey", "-noout"):
        raise ValueError("server certificate and private key do not match")
    for path in (ca_key, ca_cert, server_key, server_cert):
        path.chmod(0o600)
    print(f"Created private agent TLS materials in {directory}; SAN IP {ip}; server validity 30 days.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--address", required=True, help="Kali's verified private NAT IPv4 address")
    parser.add_argument("--directory", required=True, type=Path, help="new absolute certificate directory")
    arguments = parser.parse_args()
    try:
        prepare(arguments.address, arguments.directory)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"Agent TLS preparation failed: {error}", file=sys.stderr)
        sys.exit(1)
