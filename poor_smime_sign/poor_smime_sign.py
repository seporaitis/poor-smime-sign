# -*- coding: utf-8 -*-
from os import path
import subprocess

__all__ = ['smime_sign', 'smime_verify']

OUTPUT_FORMATS = ('SMIME', 'PEM', 'DER')

FileErrorMessage = ("{file_list} must be absolute paths to existing "
                    "files").format
FormatErrorMessage = ("{output_format}' not found in the set of supported "
                      "formats: {supported_formats}").format
OpenSSLErrorMessage = "OpenSSL failed with #{returncode}: {stderr}".format


def smime_sign(signer_cert_path, signer_key_path, content,
               output_format='SMIME',
               cert_path=None, recipient_cert_path=None):
    """Generate an S/MIME signature.

    Internally this function does nothing more, but call `openssl
    smime`. You might want to read it docs as well here:
    https://www.openssl.org/docs/manmaster/apps/smime.html

    Arguments:
    - `signer_cert_path`: string, absolute path to signer certificate file;
       the file can contain multiple certificate chain.
    - `signer_key_path`: string, absolute path to signer private key file.
    - `content`: stream-like object pointing to content that will be signed.
    - `output_format`: string, signature output format (see output formats
      below, not required).
    - `cert_path`: string, absolute path to file containing any intermediate
       certificates (not required).
    - `recipient_cert_path`: string, absolute path to recipient certificate
      file (not required).

    Output formats:
    - 'SMIME': (default)
    - 'PEM'
    - 'DER'

    Returns: string with signature.

    """
    optional_file_list = filter(bool, [cert_path, recipient_cert_path])
    file_list = [signer_cert_path, signer_key_path] + list(optional_file_list)
    if not all(path.isfile(p) and path.isabs(p) for p in file_list):
        raise ValueError(FileErrorMessage(file_list=", ".join(file_list)))

    if output_format not in OUTPUT_FORMATS:
        raise ValueError(
            FormatErrorMessage(
                output_format=output_format,
                supported_formats=", ".join(OUTPUT_FORMATS)
            )
        )

    command = [
        "openssl", "smime",
        "-binary",
        "-sign",
        "-signer", signer_cert_path,
        "-inkey", signer_key_path,
        "-outform", output_format,
    ]

    if cert_path:
        command.extend(["-certfile", cert_path])

    if recipient_cert_path:
        command.append(recipient_cert_path)

    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    stdout, stderr = process.communicate(content)

    if process.returncode:
        raise RuntimeError(
            OpenSSLErrorMessage(
                returncode=process.returncode,
                stderr=stderr,
            )
        )

    return stdout


def smime_verify(signer_cert_path, content_path, signature_path,
                 signature_format='SMIME'):
    """Verify an S/MIME signature.

    Internally this function does nothing more, but call `openssl
    smime`. You might want to read it docs as well here:
    https://www.openssl.org/docs/manmaster/apps/smime.html

    Arguments:
    - `signer_cert_path`: string, absolute path to signer certificate file.
    - `content_path`: string, absolute path to file with content that will be
      signed.
    - `signature_path`: string, absolute path to signature file.
    - `signature_format`: string, signature format (see signature formats
      below, not required).

    Signature formats:
    - 'SMIME': (default)
    - 'PEM'
    - 'DER'

    Returns: boolean - true or false.

    """
    file_list = [signer_cert_path, content_path, signature_path]
    if not all(path.isfile(p) and path.isabs(p) for p in file_list):
        raise ValueError(FileErrorMessage(file_list=", ".join(file_list)))

    if signature_format not in OUTPUT_FORMATS:
        raise ValueError(
            FormatErrorMessage(
                output_format=signature_format,
                supported_formats=", ".join(OUTPUT_FORMATS)
            )
        )

    returncode = subprocess.call(
        [
            "openssl", "smime",
            "-binary",
            "-verify",
            "-CAfile", signer_cert_path,
            "-content", content_path,
            "-in", signature_path,
            "-inform", signature_format,
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    return (returncode == 0)
