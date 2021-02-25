#!/bin/python3

import socket
import ssl
from ssl import SSLContext
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from csv import reader
# open file in read mode
with open('domains.csv', 'r') as read_obj:
    # pass the file object to reader() to get the reader object
    csv_reader = reader(read_obj)
    # Iterate over each row in the csv using reader object
    for row in csv_reader:
        try:
            # row variable is a list that represents a row in csv
            domain = row.pop()
            print("Evaluating -> " + domain)
            context: SSLContext
            context = ssl.create_default_context()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sslSocket = context.wrap_socket(s, server_hostname=domain)
            sslSocket.connect((domain, 443))
            print('Selected version by the server: ', sslSocket.version())
            sslSocket.close()
            certificate: bytes = ssl.get_server_certificate((domain, 443)).encode('utf-8')
            loaded_cert = x509.load_pem_x509_certificate(certificate, default_backend())
            common_name = loaded_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            issuer = loaded_cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            print("*** Common Name ***")
            print(common_name[0].value)
            print("*** Issuer ***")
            print(issuer.pop().value)
            san = loaded_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_dns_names = san.value.get_values_for_type(x509.DNSName)
            print("*** SAN ***")
            # print(san_dns_names)
            for record in san_dns_names:
                print(record)
        except socket.gaierror:
            print("Host Not Found")
        except ssl.SSLCertVerificationError:
            print('Could not validate certificate')
        except ssl.SSLError:
            print("Unknown TLS error")
print("Script ran successfully...")

