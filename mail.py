import os
import sys
from smtplib import (
    SMTP,
    SMTPAuthenticationError,
    SMTPDataError,
    SMTPException,
    SMTPHeloError,
    SMTPNotSupportedError,
    SMTPRecipientsRefused,
    SMTPSenderRefused,
)
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.base import Certificate

# certificate files
CA_CERT = "data/usercert.pem"
CA_KEY = "data/userkey.pem"

# smtp configuration variables
SMTP_SERVER = "smtps.alumnes.udl.cat"
SMTP_PORT = 465

# environment variables
password = os.environ.get("MAIL_PASSWORD")
mailfrom = os.environ.get("MAILFROM")
mailto = os.environ.get("MAILTO")
name_sender = os.environ.get("NAME_SENDER")
subject_mail = os.environ.get("SUBJECT")
message = os.environ.get("MESSAGE")


def assert_environment_variables():
    """
    asserts that all the environment variables (needed for the execution of the program)
    are initialized. If some variable isn't initialized, show a message and exit.
    """
    error_string = "Specify the environment variables:\n"
    if not password:
        error_string += "\tMAIL_PASSWORD (The password of the mail)\n"
    if not mailfrom:
        error_string += "\tMAIL_FROM (The source mail address)\n"
    if not mailto:
        error_string += "\tMAILTO (The destination mail)\n"
    if not name_sender:
        error_string += "\tNAME_SENDER (The name of the sender. Ex: Pablo)\n"
    if not subject_mail:
        error_string += "\tSUBJECT (The subject of the mail)\n"
    if not message:
        error_string += "\tMESSAGE (The message of the mail)\n"
    if not all([password, mailfrom, mailto, name_sender, subject_mail, message]):
        print(error_string)
        sys.exit(-1)


def get_certificate_and_key(
    cert_file: str, key_file: str
) -> Tuple[Certificate, RSAPrivateKey]:
    with open(cert_file, "rb") as cert:
        cert = x509.load_pem_x509_certificate(cert.read())
        with open(key_file, "rb") as key:
            key = serialization.load_pem_private_key(key.read(), password=b"1234")
            return cert, key


def sign_message_smime(message_b: bytes, cert: Certificate, key: RSAPrivateKey) -> bytes:
    options = [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.Text]
    return (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(message_b)
        .add_signer(cert, key, hashes.SHA512())
        .sign(serialization.Encoding.SMIME, options)
    )


def add_sender_and_subject(message_to_modify: bytes) -> str:
    """
    adds source, destination and subject to the smime message (this is needed for thunderbird)
    """
    message_decoded = message_to_modify.decode("utf-8")
    lines = message_decoded.split("\n")
    lines.insert(1, f"To: {mailto}")
    lines.insert(2, f"From: {name_sender} <{mailfrom}>")
    lines.insert(3, f"Subject: {subject_mail}")
    return "\n".join(lines)


def send_mail(message_smime: str):
    with SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
        try:
            smtp.login(mailfrom, password)
            smtp.sendmail(mailfrom, mailto, message_smime)
            print(
                f"Email sended from {mailfrom} to {mailto} with message: {message} and subject: {subject_mail}"
            )
        except (
            SMTPHeloError,
            SMTPAuthenticationError,
            SMTPNotSupportedError,
            SMTPException,
            SMTPHeloError,
            SMTPRecipientsRefused,
            SMTPSenderRefused,
            SMTPDataError,
        ) as ex:
            print(f"Error sending mail: {ex}")


def main():
    assert_environment_variables()
    certificate, key = get_certificate_and_key(CA_CERT, CA_KEY)
    message_encoded = f"{message}\n\n".encode("utf-8")
    message_smime = sign_message_smime(message_encoded, certificate, key)
    message_mail = add_sender_and_subject(message_smime)
    send_mail(message_mail)


if __name__ == "__main__":
    main()
