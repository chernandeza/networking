#!/bin/python3

import socket, ssl
import OpenSSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend

context =  context = ssl.create_default_context()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
domain = 'www.bccr.fi.cr'
sslSocket = context.wrap_socket(s, server_hostname = domain)
sslSocket.connect((domain, 443))
print('Selected version by the server: ', sslSocket.version())
sslSocket.close()

certificate: bytes = ssl.get_server_certificate(('www.bccr.fi.cr', 443)).encode('utf-8')
loaded_cert = x509.load_pem_x509_certificate(certificate, default_backend())

common_name = loaded_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
print ("*** Common Name ***")
print(common_name[0].value)


# classes must be subtype of:
#   https://cryptography.io/en/latest/x509/reference/#cryptography.x509.ExtensionType
san = loaded_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
san_dns_names = san.value.get_values_for_type(x509.DNSName)
print ("*** SAN ***")
print(san_dns_names)
