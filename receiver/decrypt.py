import os
import socket
import time

from ascon import decrypt  # your ascon package uses encrypt/decrypt
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# ----------------------------
# Receive exactly N bytes (TCP safe)
# ----------------------------
def recv_exact(conn, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed early")
        data += chunk
    return data

# ----------------------------
# Load RSA private key (KEEP ON RECEIVER ONLY)
# ----------------------------
with open("receiver_private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

HOST = "0.0.0.0"
PORT = 5000

#  Save decrypted images here
SAVE_DIR = r"C:\Users\abhijith\medical_data_receiver\static\images"
os.makedirs(SAVE_DIR, exist_ok=True)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen(5)
p
print(f"Hybrid Receiver listening on {HOST}:{PORT}")
print(f"Saving decrypted images to: {SAVE_DIR}")

count = 0

while True:
    conn, addr = server.accept()
    print("Connected from:", addr)

    try:
        # 1) Receive packet size (8 bytes)
        total_size = int.from_bytes(recv_exact(conn, 8), "big")

        # 2) Receive full packet
        packet = recv_exact(conn, total_size)

        # 3) Parse packet:
        # [2 bytes rsa_ct_len] + [rsa_ct] + [16 bytes nonce] + [ascon ciphertext+tag]
        rsa_len = int.from_bytes(packet[:2], "big")
        offset = 2

        rsa_ct = packet[offset:offset + rsa_len]
        offset += rsa_len

        nonce = packet[offset:offset + 16]
        offset += 16

        ciphertext = packet[offset:]  # includes tag at end

        # 4) RSA decrypt the ASCON session key (16 bytes)
        session_key = private_key.decrypt(
            rsa_ct,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 5) ASCON decrypt image bytes
        plaintext = decrypt(session_key, nonce, b"", ciphertext)

        if plaintext is None:
            print("Authentication failed (tampered/wrong data)")
        else:
            count += 1
            filename = os.path.join(SAVE_DIR, f"image_{count}_{int(time.time())}.jpg")
            with open(filename, "wb") as f:
                f.write(plaintext)
            print(" Saved:", filename)

    except Exception as e:
        print(" Error:", e)

    finally:
        conn.close()
