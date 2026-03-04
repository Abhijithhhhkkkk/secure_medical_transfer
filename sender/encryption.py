import os
import time
import socket
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from ascon import encrypt  # your ascon package uses encrypt/decrypt
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


WATCH_FOLDER = r"C:\Users\abhijith\ascon_demo\img"


HOST = "Receiver_lap_ip"
PORT = 5000

with open("receiver_public.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

def wait_until_file_ready(path, timeout=15):
    """Wait until file copy finishes (size stops changing)."""
    last_size = -1
    start = time.time()
    while time.time() - start < timeout:
        try:
            size = os.path.getsize(path)
        except FileNotFoundError:
            time.sleep(0.2)
            continue

        if size == last_size and size > 0:
            return True
        last_size = size
        time.sleep(0.3)
    return False

def send_image(path):
    with open(path, "rb") as f:
        image_bytes = f.read()

    # Hybrid: new ASCON key per image
    ascon_key = os.urandom(16)
    nonce = os.urandom(16)

    # ASCON encrypt image
    ciphertext = encrypt(ascon_key, nonce, b"", image_bytes)

    # RSA encrypt ASCON key (OAEP)
    rsa_ct = public_key.encrypt(
        ascon_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # Packet:
    # [2 bytes rsa_ct_len] + [rsa_ct] + [nonce] + [ciphertext+tag]
    packet = len(rsa_ct).to_bytes(2, "big") + rsa_ct + nonce + ciphertext

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))
    client.sendall(len(packet).to_bytes(8, "big"))
    client.sendall(packet)
    client.close()

class Handler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return

        path = event.src_path
        if not path.lower().endswith((".jpg", ".jpeg", ".png")):
            return

        print(" New image detected:", path)

        # Wait for copy to finish
        if not wait_until_file_ready(path):
            print(" File not ready (copy still going). Skipping:", path)
            return

        try:
            send_image(path)
            print("Sent:", os.path.basename(path))
        except Exception as e:
            print("Send failed:", e)

if __name__ == "__main__":
    os.makedirs(WATCH_FOLDER, exist_ok=True)
    print(" Watching folder:", WATCH_FOLDER)
    print(f" Sending to {HOST}:{PORT}")

    observer = Observer()
    observer.schedule(Handler(), WATCH_FOLDER, recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
