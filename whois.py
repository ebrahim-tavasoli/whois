#!/usr/bin/python3

import sys
import socket
import tldextract

WHOIS_SERVERS = {
    'ir': 'whois.nic.ir',
    'com': 'whois.internic.net',
    'net': 'whois.internic.net',
    'org': 'whois.internic.net'
}


def whois_request(server, query):
    for i in range(3):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((server, 43))

            query = query + '\r\n'
            s.send(query.encode())

            msg = b''
            while True:
                chunk = s.recv(100)
                if chunk == b'':
                    break
                msg = msg + chunk
            s.close()
            return msg.decode()
        except Exception as e:
            s.close()
            print(e)

def whois(domain: str):
    try:
        dmn = tldextract.extract(domain)
        server = WHOIS_SERVERS[dmn.suffix]
        return whois_request(server, dmn.registered_domain)
    except KeyError:
        raise KeyError('Whois server not exist')
    except Exception as e:
        raise e

try:
    print(whois(sys.argv[1]))
except KeyError:
    raise KeyError('Please tell me a domain!')
