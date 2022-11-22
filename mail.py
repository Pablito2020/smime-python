from smtplib import SMTP
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7
import os

ca_cert = "usercert.pem"
ca_key = "userkey.pem"

with open(ca_cert, 'rb') as ca_cert:
    cert = x509.load_pem_x509_certificate(ca_cert.read())
with open(ca_key, 'rb') as ca_key:
    key = serialization.load_pem_private_key(ca_key.read(), password=b'1234')
options = [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.Text]
message = pkcs7.PKCS7SignatureBuilder().set_data(b"This is a message\n\n"
).add_signer(
    cert, key, hashes.SHA512()
).sign(
    serialization.Encoding.SMIME, options
)

message = message.decode("utf-8")
m_arr = message.split("\n")
m_arr.insert(1, "To: pfa4@alumnes.udl.cat")
m_arr.insert(2, "From: Pablo Fraile Alonso <pfa4@alumnes.udl.cat>")
m_arr.insert(3, "Subject: Test")
m_arr = m_arr[:-2]
m_arr.pop(len(m_arr) - 2)
m_arr.insert(0, "Date: Tue, 22 Nov 2022 19:05:36 +0100")
# for index, element in enumerate(m_arr):
#     m_arr[index] = element.replace("\n", "")
#     m_arr[index] = element.replace("\r", "")
message = "\n".join(m_arr)
# print(message)

with SMTP("smtps.alumnes.udl.cat", 465) as smtp:
    password = os.environ.get('MAIL_PASSWORD')
    smtp.login("pfa4@alumnes.udl.cat", password)
    smtp.sendmail("pfa4@alumnes.udl.cat", "pfa4@alumnes.udl.cat", message)
