#!/bin/python
# -*- coding: utf-8 -*-

""" SSL monitoring script

Script for checking hosts SSL certificate information.

INPUT:        FQDN. Input may be:
                    - with or without "https://";
                    - with or without port defined after ":" (443 is used by default);
                    - with or without number of days defined after "#". This value will
                      be used for generating "WARNING" alerts to notify about expiring
                      certificate (30 days is used by default).

OUTPUT:       String Zabbix uses for triggers.

EXAMPLES:     python3.6 ssl_cert_checker.py "google.com"
              python3.6 ssl_cert_checker.py "https://www.google.com:443#15"

TODO:
    - Manage SEC_ERROR_REVOKED_CERTIFICATE (revoked.badssl.com)
    - Manage SSL_ERROR_BAD_CERT_DOMAIN (wrong.host.badssl.com)
"""

from collections import namedtuple
from datetime import datetime
from sys import argv, exit
from socket import socket
from OpenSSL import SSL
from idna import encode

CA_CERTS = "{{ ssl_ca_certs_location }}"


class Main:

    def __init__(self):
        self.HostInfo = namedtuple(field_names="cert fqdn peername", typename="HostInfo")
        self.certificate_verified = True
        self.san_verified = True
        self.hostname_idna = ""
        self.host_port = 443
        self.warning_threshold = 30
        self.ctx_timeout = 5

    def parse_input(self, user_input):
        """
        Parsing user provided input.

        Separating unnecessary things from FQDN, getting self.host_port and self.warning_threshold
        values if provided.

        :param user_input: argv[1] provided input
        :return: None
        """
        if user_input[:7].lower() == "http://":
            user_input = user_input[7:]
        if user_input[:8].lower() == "https://":
            user_input = user_input[8:]

        try:
            self.warning_threshold = int(user_input.split("#")[1])
            user_input = user_input.split("#")[0]
        except IndexError:
            pass

        try:
            self.hostname_idna = user_input = user_input.split("/")[0]
        except IndexError:
            self.hostname_idna = user_input

        try:
            self.hostname_idna = user_input.split(":")[0]
            self.host_port = int(user_input.split(":")[1])
        except IndexError:
            self.hostname_idna = user_input

    def verify_callback(self, conn, x509, errno, errdepth, retcode=True):
        """
        Callback for certificate validation.

        Inputs are a bunch of parameters needed for SSL.Context.set_verify() function.

        :return: True if verification passes and False otherwise
        """
        if errno != 0 or (errdepth == 0 and not self.verify_domain(x509)):
            return False
        return True

    def get_san_information(self, x509):
        """
        Get Subject Alternative Names information.

        :param x509: Peer certificate
        :return: List with Subject Alternative Names
        """
        cert_san = []
        for i in range(0, x509.get_extension_count()):
            if "subjectAltName" in str(x509.get_extension(i).get_short_name()):
                cert_san = [dns.strip("DNS:").strip(",") for dns in x509.get_extension(i).__str__().split() if
                            x509.get_extension(i).__str__() != "CA:FALSE"]
        return cert_san

    def verify_domain(self, x509):
        """
        Searching for problems in peers certificate.

        :param x509: Peer certificate
        :return: True if domain certificate is verified, False otherwise
        """
        cert_san = self.get_san_information(x509)

        # Verify peer on Subject Alternative Names
        dns_found_in_san = False
        if cert_san:
            for dns in cert_san:
                if (dns[:2] == "*." and self.hostname_idna[-len(dns[2:]):] == dns[2:]) or \
                        (self.hostname_idna == dns):
                    dns_found_in_san = True

        if not dns_found_in_san:
            self.san_verified = False

        return True

    def get_certificate(self):
        """
        Perform handshake and get certificate.

        This function will not fail if SSL connection won't get verified. Instead, it will call itself up
        again with SSL.VERIFY_NONE option. This is needed for collecting information even if after
        failed verification.

        :return: HostInfo namedtuple containing peer information.
        """
        sock = socket()

        try:
            sock.settimeout(self.ctx_timeout)
            sock.connect((self.hostname_idna, self.host_port))
            sock.setblocking(True)
        except (ConnectionRefusedError, Exception) as e:
            print(f"SSL check failed: {e}")
            exit(1)

        peername = sock.getpeername()
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        ctx.set_timeout(self.ctx_timeout)

        if self.certificate_verified:
            ctx.load_verify_locations(CA_CERTS)
            ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT | SSL.VERIFY_CLIENT_ONCE, self.verify_callback)
        else:
            ctx.verify_mode = SSL.VERIFY_NONE

        ssl_sock = SSL.Connection(ctx, sock)
        ssl_sock.set_connect_state()
        ssl_sock.set_tlsext_host_name(encode(self.hostname_idna))

        try:
            ssl_sock.do_handshake()
            x509 = ssl_sock.get_peer_certificate()
            ssl_sock.shutdown()
            ssl_sock.close()
            sock.close()
            return self.HostInfo(cert=x509, peername=peername, fqdn=self.hostname_idna)
        except SSL.Error as e:
            e = e.__str__().strip("[()]").split(",")
            if e != [""] and "wrong version number" in e[2]:
                print("SSL check failed: Connection refused. Wrong port or disabled SSL.")
                ssl_sock.close()
                sock.close()
                exit(1)
            if e != [""] and "handshake failure" in e[2]:
                print("SSL check failed: Unable to negotiate a handshake.")
                ssl_sock.close()
                sock.close()
                exit(1)
            ssl_sock.close()
            sock.close()
            self.certificate_verified = False
            return self.get_certificate()

    def get_issue_date(self, host_info):
        return datetime.strptime(host_info.cert.get_notBefore().decode("utf-8"), "%Y%m%d%H%M%SZ")

    def get_expiration_date(self, host_info):
        return datetime.strptime(host_info.cert.get_notAfter().decode("utf-8"), "%Y%m%d%H%M%SZ")

    def get_days_to_expiration(self, host_info):
        date = (self.get_expiration_date(host_info) - datetime.now()).days
        return 0 if date < 0 else date

    def get_output(self, host_info):
        """
        Build output.

        :param host_info: hosts certificate info
        :return: list of messages
        """
        output = []

        try:
            if self.get_days_to_expiration(host_info) <= self.warning_threshold:
                output.append(f"SSL certificate will expire in {self.get_days_to_expiration(host_info)} days")
            else:
                output.append(f"Valid for {self.get_days_to_expiration(host_info)} days")

            if not self.san_verified:
                output.append("Subject Alternative Names verification failed")

            if not self.certificate_verified:
                output.append(f"Certificate verification failed (issuer: {host_info.cert.get_issuer().commonName})")

            if host_info.cert.has_expired():
                output = [f"Certificate expired ({self.get_issue_date(host_info).date()} – {self.get_expiration_date(host_info).date()})"]

        except Exception as e:
            print(f"SSL check failed: {e}")
            exit(1)

        return output

    def main(self, user_input):
        try:
            self.parse_input(user_input)
            host_info = self.get_certificate()
            output = self.get_output(host_info)

            if type(output) == list:
                print("; ".join(output))
            else:
                print("SSL check failed: An error occurred during output parsing")

        except Exception as e:
            print(f"SSL check failed: {e}")
            exit(1)


if __name__ == "__main__":
    app = Main()
    app.main(argv[1])
