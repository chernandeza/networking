#!/bin/python3
import csv
import socket
import ssl
from ssl import SSLContext
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from csv import reader

# Create results file
with open('results.csv', 'w') as f1:
    writer = csv.writer(f1, delimiter='\t', lineterminator='\n', quoting=csv.QUOTE_ALL)
    writer.writerow(["Domain", "TLSVersion", "CommonName", "WildcardCN", "CertIssuer", "SAN"])
    f1.close()

# open file in read mode
with open('domains.csv', 'r') as read_obj:
    # pass the file object to reader() to get the reader object
    csv_reader = reader(read_obj)
    # Iterate over each row in the csv using reader object
    for row in csv_reader:
        try:
            # row variable is a list that represents a row in csv
            wildcardCN = False  # Tells if "*" was found on either CN or SAN
            domain = row.pop()
            print("Evaluating -> " + domain)
            context: SSLContext
            context = ssl.create_default_context()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sslSocket = context.wrap_socket(s, server_hostname=domain)
            sslSocket.connect((domain, 443))  # Establishes TLS connection to host
            # print('Selected version by the server: ', sslSocket.version())
            tlsVersion = sslSocket.version()  # Extracts TLS version used to establish connection.
            sslSocket.close()
            certificate: bytes = ssl.get_server_certificate((domain, 443)).encode('utf-8')  #
            loaded_cert = x509.load_pem_x509_certificate(certificate, default_backend())
            common_name = loaded_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            issuer = loaded_cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            # print("*** Common Name ***")
            # print(common_name[0].value)
            commonName = common_name[0].rfc4514_string()
            if "*" in commonName:
                wildcardCN = True
                print("Found wildcard CN")
                print(commonName)
            # print("*** Issuer ***")
            # print(issuer.pop().value)
            certIssuer = issuer.pop().value
            print(certIssuer)
            san = loaded_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_dns_names = san.value.get_values_for_type(x509.DNSName)
            # print("*** SAN ***")
            # print(san_dns_names)
            if any("*" in s for s in san_dns_names):
                wildcardCN = True
                print("Found wildcard SAN")
            with open('results.csv', 'a+') as f1:
                writer = csv.writer(f1, delimiter='\t', lineterminator='\n', quoting=csv.QUOTE_ALL)
                writer.writerow([domain, tlsVersion, commonName, wildcardCN, certIssuer, san_dns_names])
                f1.close()
        except socket.gaierror:
            print("Host Not Found")
        except ssl.SSLCertVerificationError:
            print('Could not validate certificate')
        except ssl.SSLError:
            print("Unknown TLS error")

print("Validation complete...")



