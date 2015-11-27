# -*- coding: utf-8 -*-
from os import path
from cStringIO import StringIO
import subprocess


OUTPUT_FORMATS = {'SMIME', 'PEM', 'DER'}


def smime_sign(signer_cert, signer_key, recipient_cert, content, output_format):
    """Generate an S/MIME signature.

    Internally this function does nothing more, but call `openssl
    smime`. You might want to read it docs as well here:
    https://www.openssl.org/docs/manmaster/apps/smime.html

    Arguments:
    - `signer_cert`: string, absolute path to signer certificate file.
    - `signer_key`: string, absolute path to signer private key file.
    - `recipient_cert`: string, absolute path to recipient certificate file.
    - `content`: stream-like object pointing to content that will be signed.
    - `output_format`: string, signature output format (see output formats below).

    Output formats:
    - 'SMIME': (default)
    - 'PEM'
    - 'DER'

    Returns: string with signature.

    """
    if not all(path.isfile(p) and path.isabs(p) for p in [signer_cert, signer_key, recipient_cert]):
        raise ValueError("`signer_cert`, `signer_key` and `recipient_cert` all have to be absolute paths to existing files.")

    if not output_format in OUTPUT_FORMATS:
        raise ValueError("`output_format` '{output_format}' not found in the set of supported formats: {supported_formats}".format(
            output_format=output_format,
            supported_formats=", ".join(OUTPUT_FORMATS),
        ))

    stdout = StringIO()
    stderr = StringIO()

    process = subprocess.Popen(
        [
            "openssl", "smime",
            "-binary",
            "-sign",
            "-signer", signer_cert,
            "-inkey", signer_key,
            "-outform", output_format,
            recipient_cert
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    stdout, stderr = process.communicate(content)

    if process.returncode:
        raise RuntimeError("OpenSSL failed with #{returncode}: {stderr}".format(
            returncode=process.returncode,
            stderr=stderr.getvalue(),
        ))

    return stdout
