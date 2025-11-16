cd ~/Desktop/securechat-skeleton

cat > verify_tamper.py << 'EOF'
import json
from pathlib import Path

from cryptography import x509

from app.common.utils import b64_decode
from app.common.protocol import ChatMsg
from app.crypto import sign as rsa_sign

# Use one of YOUR actual transcript files:
TRANSCRIPT_PATH = "session-1763286456-client.log"

# Both certs, because this server-side log contains messages from server and client
SERVER_CERT_PATH = "certs/server_cert.pem"
CLIENT_CERT_PATH = "certs/client_cert.pem"


def main():
    server_cert = x509.load_pem_x509_certificate(Path(SERVER_CERT_PATH).read_bytes())
    client_cert = x509.load_pem_x509_certificate(Path(CLIENT_CERT_PATH).read_bytes())

    server_pub = server_cert.public_key()
    client_pub = client_cert.public_key()

    with open(TRANSCRIPT_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            obj = json.loads(line)
            if obj.get("type") != "msg":
                continue

            msg = ChatMsg(**obj)
            ct_b64 = msg.ct
            to_verify = f"{msg.seqno}|{msg.ts}|{ct_b64}".encode("utf-8")
            sig_bytes = b64_decode(msg.sig)

            # Try verifying with server key first, then client key
            if rsa_sign.verify_signature(server_pub, to_verify, sig_bytes):
                who = "server"
                ok = True
            elif rsa_sign.verify_signature(client_pub, to_verify, sig_bytes):
                who = "client"
                ok = True
            else:
                who = "unknown"
                ok = False

            print(f"seq={msg.seqno} from={who} sig_ok={ok}")


if __name__ == "__main__":
    main()
EOF
