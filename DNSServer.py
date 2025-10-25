
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rrset
import socket
import threading
import signal
import os
import sys

import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = kdf.derive(password.encode('utf-8'))
    key = base64.urlsafe_b64encode(key)
    return key

def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(input_string.encode('utf-8'))  # BYTES
    return encrypted_data    

def decrypt_with_aes(encrypted_data, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    if isinstance(encrypted_data, str):
        encrypted_data = encrypted_data.encode('utf-8')
    decrypted_data = f.decrypt(encrypted_data)  # BYTES in -> BYTES out
    return decrypted_data.decode('utf-8')

# === Assignment exfil parameters ===
salt = b'Tandon'  # byte-object
password = "amv9978@nyu.edu"
input_string = "AlwaysWatching"

encrypted_value = encrypt_with_aes(input_string, password, salt)  # BYTES token
token_str = encrypted_value.decode('utf-8')  # STRING for TXT

def generate_sha256_hash(input_string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    return sha256_hash.hexdigest()

# Minimal set of records
dns_records = {
    'example.com.': {
        dns.rdatatype.A: '93.184.216.34',
        dns.rdatatype.NS: 'ns.example.com.',
        dns.rdatatype.TXT: ('This is a TXT record',),
        dns.rdatatype.MX: [(10, 'mail.example.com.')],
    },
    'safebank.com.': { dns.rdatatype.A: '192.168.1.102' },
    'google.com.':   { dns.rdatatype.A: '192.168.1.103' },
    'legitsite.com.':{ dns.rdatatype.A: '192.168.1.104' },
    'yahoo.com.':    { dns.rdatatype.A: '192.168.1.105' },
    'nyu.edu.': {
        dns.rdatatype.A: '192.168.1.106',
        # Store a STRING-CAST version of your encrypted data (per assignment)
        dns.rdatatype.TXT: (token_str,),
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        dns.rdatatype.NS: 'ns1.nyu.edu.',
    },
}

def run_dns_server(bind_ip="127.0.0.1", port=53):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((bind_ip, port))

    while True:
        try:
            data, addr = server_socket.recvfrom(2048)
            request = dns.message.from_wire(data)
            response = dns.message.make_response(request)
            question = request.question[0]
            qname = str(question.name)
            qtype = question.rdtype

            if qname in dns_records and qtype in dns_records[qname]:
                answer_data = dns_records[qname][qtype]
                rdata_list = []

                if qtype == dns.rdatatype.MX:
                    for pref, server in answer_data:
                        # Build from text is fine for MX
                        rdata_list.append(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.MX, f"{pref} {server}"))
                elif qtype == dns.rdatatype.TXT:
                    # Build TXT rdata using bytes to avoid any quoting/splitting surprises
                    token = answer_data[0] if isinstance(answer_data, (tuple, list)) else str(answer_data)
                    token_bytes = token.encode('utf-8')
                    from dns.rdtypes.ANY.TXT import TXT
                    rdata_list.append(TXT(dns.rdataclass.IN, dns.rdatatype.TXT, strings=[token_bytes]))
                elif isinstance(answer_data, str):
                    rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, answer_data)]
                else:
                    rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, data) for data in answer_data]

                if rdata_list:
                    rrset = dns.rrset.RRset(question.name, dns.rdataclass.IN, qtype)
                    for rdata in rdata_list:
                        rrset.add(rdata)
                    response.answer.append(rrset)

            response.flags |= 1 << 10
            # Debug logging for TXT responses
            if qname == 'nyu.edu.' and qtype == dns.rdatatype.TXT:
                print("DEBUG TXT to send:", token_str)
            print("Responding to request:", qname)
            server_socket.sendto(response.to_wire(), addr)
        except KeyboardInterrupt:
            print('\nExiting...')
            server_socket.close()
            sys.exit(0)
        except Exception as e:
            print('Error handling request:', e)

def run_dns_server_user():
    print("Input 'q' and hit 'enter' to quit")
    print("DNS server is running...")

    def user_input():
        while True:
            cmd = input()
            if cmd.lower() == 'q':
                print('Quitting...')
                os.kill(os.getpid(), signal.SIGINT)

    input_thread = threading.Thread(target=user_input, daemon=True)
    input_thread.start()
    run_dns_server()

if __name__ == '__main__':
    run_dns_server_user()
