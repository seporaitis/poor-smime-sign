#!/usr/bin/env python
# -*- coding: utf-8 -*-

from os import path
import unittest
import tempfile

from poor_smime_sign import smime_sign, smime_verify


def _read_file(abs_path):
        with open(abs_path, 'rb') as f:
            return f.read()


def _file_fixture(rel_path):
    return path.join(path.dirname(__file__), rel_path)


class PoorSmimeSignTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.signer_cert_path = _file_fixture("files/signer.cert")
        cls.signer_key_path = _file_fixture("files/signer.pem")
        cls.cert_path = _file_fixture("files/recipient.cert")
        cls.recipient_cert_path = _file_fixture("files/recipient.cert")
        cls.manifest_json_path = _file_fixture("files/manifest.json")

        cls.signature_smime_path = _file_fixture("files/signature.smime")
        cls.signature_pem_path = _file_fixture("files/signature.pem")
        cls.signature_der_path = _file_fixture("files/signature.der")

        cls.signature_smime = _read_file(cls.signature_smime_path)
        cls.signature_pem = _read_file(cls.signature_pem_path)
        cls.signature_der = _read_file(cls.signature_der_path)

        cls.maniphest_json = _read_file(cls.manifest_json_path)

    def test_smime_fixture(self):
        self.assertTrue(
            smime_verify(
                signer_cert_path=self.signer_cert_path,
                content_path=self.manifest_json_path,
                signature_path=self.signature_smime_path,
                signature_format='SMIME',
            )
        )

    def test_pem_fixture(self):
        self.assertTrue(
            smime_verify(
                signer_cert_path=self.signer_cert_path,
                content_path=self.manifest_json_path,
                signature_path=self.signature_pem_path,
                signature_format='PEM',
            )
        )

    def test_der_fixture(self):
        self.assertTrue(
            smime_verify(
                signer_cert_path=self.signer_cert_path,
                content_path=self.manifest_json_path,
                signature_path=self.signature_der_path,
                signature_format='DER',
            )
        )

    def test_smime_format_no_recipient(self):
        actual_smime = smime_sign(
            signer_cert_path=self.signer_cert_path,
            signer_key_path=self.signer_key_path,
            cert_path=self.cert_path,
            recipient_cert_path=None,
            content=self.maniphest_json,
            output_format='SMIME',
        )

        with tempfile.NamedTemporaryFile(delete=True) as temp:
            temp.write(actual_smime)
            temp.flush()

            self.assertTrue(
                smime_verify(
                    signer_cert_path=self.signer_cert_path,
                    content_path=self.manifest_json_path,
                    signature_path=path.abspath(temp.name),
                    signature_format='SMIME',
                )
            )

    def test_pem_format_no_recipient(self):
        actual_smime = smime_sign(
            signer_cert_path=self.signer_cert_path,
            signer_key_path=self.signer_key_path,
            cert_path=self.cert_path,
            recipient_cert_path=None,
            content=self.maniphest_json,
            output_format='PEM',
        )

        with tempfile.NamedTemporaryFile(delete=True) as temp:
            temp.write(actual_smime)
            temp.flush()

            self.assertTrue(
                smime_verify(
                    signer_cert_path=self.signer_cert_path,
                    content_path=self.manifest_json_path,
                    signature_path=path.abspath(temp.name),
                    signature_format='PEM',
                )
            )

    def test_der_format_no_recipient(self):
        actual_smime = smime_sign(
            signer_cert_path=self.signer_cert_path,
            signer_key_path=self.signer_key_path,
            cert_path=self.cert_path,
            recipient_cert_path=None,
            content=self.maniphest_json,
            output_format='DER',
        )

        with tempfile.NamedTemporaryFile(delete=True) as temp:
            temp.write(actual_smime)
            temp.flush()

            self.assertTrue(
                smime_verify(
                    signer_cert_path=self.signer_cert_path,
                    content_path=self.manifest_json_path,
                    signature_path=path.abspath(temp.name),
                    signature_format='DER',
                )
            )

    def test_smime_format_no_certs(self):
        actual_smime = smime_sign(
            signer_cert_path=self.signer_cert_path,
            signer_key_path=self.signer_key_path,
            cert_path=None,
            recipient_cert_path=self.recipient_cert_path,
            content=self.maniphest_json,
            output_format='SMIME',
        )

        with tempfile.NamedTemporaryFile(delete=True) as temp:
            temp.write(actual_smime)
            temp.flush()

            self.assertTrue(
                smime_verify(
                    signer_cert_path=self.signer_cert_path,
                    content_path=self.manifest_json_path,
                    signature_path=path.abspath(temp.name),
                    signature_format='SMIME',
                )
            )

    def test_pem_format_no_certs(self):
        actual_smime = smime_sign(
            signer_cert_path=self.signer_cert_path,
            signer_key_path=self.signer_key_path,
            cert_path=None,
            recipient_cert_path=self.recipient_cert_path,
            content=self.maniphest_json,
            output_format='PEM',
        )

        with tempfile.NamedTemporaryFile(delete=True) as temp:
            temp.write(actual_smime)
            temp.flush()

            self.assertTrue(
                smime_verify(
                    signer_cert_path=self.signer_cert_path,
                    content_path=self.manifest_json_path,
                    signature_path=path.abspath(temp.name),
                    signature_format='PEM',
                )
            )

    def test_der_format_no_certs(self):
        actual_smime = smime_sign(
            signer_cert_path=self.signer_cert_path,
            signer_key_path=self.signer_key_path,
            cert_path=None,
            recipient_cert_path=self.recipient_cert_path,
            content=self.maniphest_json,
            output_format='DER',
        )

        with tempfile.NamedTemporaryFile(delete=True) as temp:
            temp.write(actual_smime)
            temp.flush()

            self.assertTrue(
                smime_verify(
                    signer_cert_path=self.signer_cert_path,
                    content_path=self.manifest_json_path,
                    signature_path=path.abspath(temp.name),
                    signature_format='DER',
                )
            )

    def test_inconsistent_check(self):
        actual_smime = smime_sign(
            signer_cert_path=self.signer_cert_path,
            signer_key_path=self.signer_key_path,
            cert_path=self.cert_path,
            recipient_cert_path=self.recipient_cert_path,
            content=self.maniphest_json,
            output_format='SMIME',
        )

        with tempfile.NamedTemporaryFile(delete=True) as temp:
            temp.write(actual_smime)
            temp.flush()

            self.assertFalse(
                smime_verify(
                    signer_cert_path=self.signer_cert_path,
                    content_path=self.manifest_json_path,
                    signature_path=path.abspath(temp.name),
                    signature_format='PEM',
                )
            )

    def test_relative_signer_cert_error(self):
        relative_signer_cert = "files/signer.cert"

        with self.assertRaises(ValueError) as ctx:
            smime_sign(
                signer_cert_path=relative_signer_cert,
                signer_key_path=self.signer_key_path,
                cert_path=self.cert_path,
                recipient_cert_path=self.recipient_cert_path,
                content=self.maniphest_json,
                output_format='SMIME',
            )

        self.assertEqual(
            str(ctx.exception),
            "{file_list} must be absolute paths to existing files".format(
                file_list=", ".join([
                    relative_signer_cert,
                    self.signer_key_path,
                    self.cert_path,
                    self.recipient_cert_path,
                ]),
            )
        )

    def test_relative_signer_key_error(self):
        relative_signer_key = "files/signer.pem"

        with self.assertRaises(ValueError) as ctx:
            smime_sign(
                signer_cert_path=self.signer_cert_path,
                signer_key_path=relative_signer_key,
                cert_path=self.cert_path,
                recipient_cert_path=self.recipient_cert_path,
                content=self.maniphest_json,
                output_format='SMIME',
            )

        self.assertEqual(
            str(ctx.exception),
            "{file_list} must be absolute paths to existing files".format(
                file_list=", ".join([
                    self.signer_cert_path,
                    relative_signer_key,
                    self.cert_path,
                    self.recipient_cert_path,
                ]),
            )
        )

    def test_relative_recipient_cert_error(self):
        relative_recipient_cert = "files/recipient.pem"

        with self.assertRaises(ValueError) as ctx:
            smime_sign(
                signer_cert_path=self.signer_cert_path,
                signer_key_path=self.signer_key_path,
                cert_path=self.cert_path,
                recipient_cert_path=relative_recipient_cert,
                content=self.maniphest_json,
                output_format='SMIME',
            )

        self.assertEqual(
            str(ctx.exception),
            "{file_list} must be absolute paths to existing files".format(
                file_list=", ".join([
                    self.signer_cert_path,
                    self.signer_key_path,
                    self.cert_path,
                    relative_recipient_cert,
                ]),
            )
        )

    def test_incorrect_format_error(self):
        with self.assertRaises(ValueError) as ctx:
            smime_sign(
                signer_cert_path=self.signer_cert_path,
                signer_key_path=self.signer_key_path,
                cert_path=self.cert_path,
                recipient_cert_path=self.recipient_cert_path,
                content=self.maniphest_json,
                output_format='INCORRECT',
            )

        self.assertEqual(
            str(ctx.exception),
            ("{output_format}' not found in the set of supported "
             "formats: {supported_formats}").format(
                 output_format='INCORRECT',
                 supported_formats=", ".join(('SMIME', 'PEM', 'DER')),
            )
        )

    def test_runtime_error(self):
        with self.assertRaises(RuntimeError) as ctx:
            smime_sign(
                signer_cert_path=self.signer_key_path,
                signer_key_path=self.recipient_cert_path,
                cert_path=self.cert_path,
                recipient_cert_path=self.signer_key_path,
                content=self.maniphest_json,
                output_format='PEM',
            )

        self.assertRegexpMatches(
            str(ctx.exception), r'OpenSSL failed with #[\d]+: .*'
        )


if __name__ == '__main__':
    import sys
    sys.exit(unittest.main())
