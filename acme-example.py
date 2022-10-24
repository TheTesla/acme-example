#!/usr/bin/env python3

# Based on https://github.com/certbot/certbot/blob/529942fe4b8f5000d801e1e99a2260850b05dd31/acme/examples/http01_example.py




from contextlib import contextmanager

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
import josepy as jose

from acme import challenges
from acme import client
from acme import crypto_util
from acme import messages
from acme import standalone

DIRECTORY_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'
USER_AGENT = 'python-acme-example'
ACC_KEY_BITS = 2048
CERT_PKEY_BITS = 2048
DOMAIN = 'testserver.smartrns.net'
PORT = 80

def new_csr_comp(domain_name, pkey_pem=None):
    """Create certificate signing request."""
    if pkey_pem is None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=CERT_PKEY_BITS, backend=default_backend())
        pkey_pem = key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption())
    csr_pem = crypto_util.make_csr(pkey_pem, [domain_name])
    return pkey_pem, csr_pem


def select_http01_chall(orderr):
    """Extract authorization resource from within order resource."""
    for authz in orderr.authorizations:
        for i in authz.body.challenges:
            if isinstance(i.chall, challenges.HTTP01):
                return i
    raise Exception('HTTP-01 challenge was not offered by the CA server.')

@contextmanager
def challenge_server(http_01_resources):
    """Manage standalone server set up and shutdown."""
    try:
        servers = standalone.HTTP01DualNetworkedServers(('', PORT), http_01_resources)
        servers.serve_forever()
        yield servers
    finally:
        servers.shutdown_and_server_close()

def perform_http01(client_acme, challb, orderr):
    """Set up standalone webserver and perform HTTP-01 challenge."""
    response, validation = challb.response_and_validation(client_acme.net.key)
    resource = standalone.HTTP01RequestHandler.HTTP01Resource(
        chall=challb.chall, response=response, validation=validation)
    with challenge_server({resource}):
        client_acme.answer_challenge(challb, response)
        finalized_orderr = client_acme.poll_and_finalize(orderr)
    return finalized_orderr.fullchain_pem




def example_http():
    """This example executes the whole process of fulfilling a HTTP-01
    challenge for one specific domain.

    The workflow consists of:
    (Account creation)
    - Create account key
    - Register account and accept TOS
    (Certificate actions)
    - Select HTTP-01 within offered challenges by the CA server
    - Set up http challenge resource
    - Set up standalone web server
    - Create domain private key and CSR
    - Issue certificate
    - Renew certificate
    - Deactivate Account

    """
    # Create account key
    acc_key = jose.JWKRSA(key=rsa.generate_private_key(public_exponent=65537,key_size=ACC_KEY_BITS,backend=default_backend()))

    # Register account and accept TOS

    net = client.ClientNetwork(acc_key, user_agent=USER_AGENT)
    directory = messages.Directory.from_json(net.get(DIRECTORY_URL).json())
    client_acme = client.ClientV2(directory, net=net)

    # Terms of Service URL is in client_acme.directory.meta.terms_of_service
    # Registration Resource: regr
    # Creates account with contact information.
    email = ('stefan.helmert@t-online.de')
    regr = client_acme.new_account(messages.NewRegistration.from_data(email=email,terms_of_service_agreed=True))

    # Create domain private key and CSR
    pkey_pem, csr_pem = new_csr_comp(DOMAIN)

    # Issue certificate
    orderr = client_acme.new_order(csr_pem)

    # Select HTTP-01 within offered challenges by the CA server
    challb = select_http01_chall(orderr)

    # The certificate is ready to be used in the variable "fullchain_pem".
    fullchain_pem = perform_http01(client_acme, challb, orderr)
    with open('fullchain.pem', 'wt') as pem:
        pem.write(fullchain_pem)


    # Renew certificate
    _, csr_pem = new_csr_comp(DOMAIN, pkey_pem)

    orderr = client_acme.new_order(csr_pem)

    challb = select_http01_chall(orderr)

    # Performing challenge
    fullchain_pem = perform_http01(client_acme, challb, orderr)
    with open('fullchain_renewed.pem', 'wt') as pem:
        pem.write(fullchain_pem)


    # Deactivate account/registration
    regr = client_acme.deactivate_registration(regr)

if __name__ == "__main__":
    example_http()


