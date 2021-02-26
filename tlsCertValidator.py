#!/bin/python3
import csv
import socket
import ssl
from ssl import SSLContext

import cryptography
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from csv import reader

# Create results file and add Header row
with open('results.csv', 'w') as f1:
    writer = csv.writer(f1, delimiter='\t', lineterminator='\n', quoting=csv.QUOTE_ALL)
    writer.writerow(["Domain", "TLSVersion", "CommonName", "WildcardCN", "CertIssuer", "SAN"])
    f1.close()

# Declare counters
countSuccess = 0
countFail = 0

# open input file in read mode
with open('domains.csv', 'r') as read_obj:
    # pass the file object to reader() to get the reader object
    csv_reader = reader(read_obj)
    # Iterate over each row in the csv using reader object
    for row in csv_reader:
        try:
            # Variable declaration and cleanup #
            tlsVersion = "NULL"
            commonName = "NULL"
            certIssuer = "NULL"
            san_dns_names = "NULL"
            # --- First, we validate TLS protocol version --- #
            # row variable is a list that represents a row in csv
            wildcardCN = False  # True if "*" was found on either CN or SAN
            url: str = row.pop()

            # Removes everything after first "/" is found
            domain = url.split("/", 1)[0]

            print("Evaluating -> " + domain)
            context: SSLContext
            context = ssl.create_default_context()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sslSocket = context.wrap_socket(s, server_hostname=domain)
            sslSocket.connect((domain, 443))  # Establishes TLS connection to host
            # print('Selected version by the server: ', sslSocket.version())
            tlsVersion = sslSocket.version()  # Extracts TLS version used to establish connection.
            sslSocket.close()

            # --- Now, validate certificate properties --- #
            # Obtains certificate from connection
            certificate: bytes = ssl.get_server_certificate((domain, 443)).encode('utf-8')
            loaded_cert = x509.load_pem_x509_certificate(certificate, default_backend())
            # Gets CN from certificate #
            common_name = loaded_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)

            # Gets Issuer name from certificate #
            issuer = loaded_cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            # print("*** Issuer ***")
            certIssuer = issuer.pop().value
            # print(certIssuer)

            # print("*** Common Name ***")
            # print(common_name[0].value)
            commonName = common_name[0].rfc4514_string()
            if "*" in commonName:  # Search for wildcard on Common Name
                wildcardCN = True
                print("... Domain is using wildcard CN")
                # print(commonName)

            # Gets SAN from certificate attributes
            san = loaded_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_dns_names = san.value.get_values_for_type(x509.DNSName)
            # print("*** SAN ***")
            # print(san_dns_names)
            if any("*" in s for s in san_dns_names):  # Search for wildcard on SAN List
                wildcardCN = True
                print("... Domain is using wildcard SAN")
            with open('results.csv', 'a+') as f1:
                writer = csv.writer(f1, delimiter='\t', lineterminator='\n', quoting=csv.QUOTE_ALL)
                writer.writerow([domain, tlsVersion, commonName, wildcardCN, certIssuer, san_dns_names])
                f1.close()
                countSuccess += 1

        except socket.gaierror:
            print("Host Not Found")
            with open('results.csv', 'a+') as f1:
                writer = csv.writer(f1, delimiter='\t', lineterminator='\n', quoting=csv.QUOTE_ALL)
                writer.writerow([domain, tlsVersion, commonName, wildcardCN, certIssuer, san_dns_names])
                f1.close()
                countFail += 1
        except ssl.SSLCertVerificationError:
            print('Could not validate certificate')
            with open('results.csv', 'a+') as f1:
                writer = csv.writer(f1, delimiter='\t', lineterminator='\n', quoting=csv.QUOTE_ALL)
                writer.writerow([domain, tlsVersion, commonName, wildcardCN, certIssuer, san_dns_names])
                f1.close()
                countFail += 1
        except ssl.SSLError:
            print("Unknown TLS error")
            with open('results.csv', 'a+') as f1:
                writer = csv.writer(f1, delimiter='\t', lineterminator='\n', quoting=csv.QUOTE_ALL)
                writer.writerow([domain, tlsVersion, commonName, wildcardCN, certIssuer, san_dns_names])
                f1.close()
                countFail += 1
        except ConnectionRefusedError:
            print("Connection Refused error")
            with open('results.csv', 'a+') as f1:
                writer = csv.writer(f1, delimiter='\t', lineterminator='\n', quoting=csv.QUOTE_ALL)
                writer.writerow([domain, tlsVersion, commonName, wildcardCN, certIssuer, san_dns_names])
                f1.close()
                countFail += 1
        except IndexError:
            print("Found empty line on file... Probably EOF.")
        except cryptography.x509.extensions.ExtensionNotFound:
            print("Certificate has no extensions")

print("Validation complete...")
print("Found information successfully for {0} domains".format(countSuccess))
print("Information missing or errors found on {0} domains".format(countFail))
