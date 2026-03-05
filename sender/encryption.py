import os
import time
import socket
from pathlib import Path

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from ascon import encrypt  # your ascon package
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# ----------------------------
# CONFIG (Pi)
# ----------------------------
WATCH_FOLDER = Path("/home/pi/ascon_demo/img")

# Receiver laptop IP
HOST = os.getenv("RECEIVER_IP", "192.168.1.98")   # <-- set your laptop IP here
PORT = 5000

PUBLIC_KEY_PATH = Path("/home/pi/ascon_demo/keys/receiver_public.pem")

SOCKET_TIMEOUT = 10

READY_TIMEOUT = 20
READY_STABLE_CHECKS = 4
READY_SLEEP = 0.3


# ----------------------------
# Load RSA public key (receiver's public key)
# ----------------------------
with open(PUBLIC_KEY_PATH, "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())


def wait_until_file_ready(path: Path, timeout=READY_TIMEOUT) -> bool:
    stable = 0
    last_size = -1
    start = time.time()

    while time.time() - start < timeout:
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            time.sleep(0.2)
            continue

        if size > 0 and size == last_size:
            stable += 1
            if stable >= READY_STABLE_CHECKS:
                return True
        else:
            stable = 0

        last_size = size
        time.sleep(READY_SLEEP)

    return False


def send_image(path: Path) -> None:
    image_bytes = path.read_bytes()

    # Metadata
    filename = path.name.encode("utf-8", errors="replace")
    if len(filename) > 500:
        filename = filename[:500]  # keep header small

    ts = int(time.time())
    packet_id = os.urandom(16)

    # Hybrid: new ASCON key per image
    ascon_key = os.urandom(16)
    nonce = os.urandom(16)

    # AAD (must match receiver)
    aad = len(filename).to_bytes(2, "big") + filename + ts.to_bytes(8, "big") + packet_id

    # ASCON encrypt image
    ciphertext = encrypt(ascon_key, nonce, aad, image_bytes)

    # RSA encrypt ASCON key (OAEP)
    rsa_ct = public_key.encrypt(
        ascon_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    if len(rsa_ct) > 65535:
        raise ValueError("RSA ciphertext too long to fit in 2 bytes length field.")

    # Packet format:
    # [2 bytes rsa_len] [rsa_ct] [16 nonce] [2 name_len] [name bytes] [8 timestamp] [16 packet_id] [ciphertext+tag]
    packet = (
        len(rsa_ct).to_bytes(2, "big")
        + rsa_ct
        + nonce
        + len(filename).to_bytes(2, "big")
        + filename
        + ts.to_bytes(8, "big")
        + packet_id
        + ciphertext
    )

    # Send with total length prefix (8 bytes)
    with socket.create_connection((HOST, PORT), timeout=SOCKET_TIMEOUT) as client:
        client.sendall(len(packet).to_bytes(8, "big"))
        client.sendall(packet)


class Handler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return

        path = Path(event.src_path)

        # Ignore temp/partial files
        if path.name.startswith(".") or path.suffix.lower() in [".part", ".tmp", ".crdownload"]:
            return

        if path.suffix.lower() not in [".jpg", ".jpeg", ".png"]:
            return

        print(f"📷 New image detected: {path}")

        if not wait_until_file_ready(path):
            print(f"File not ready. Skipping: {path}")
            return

        try:
            send_image(path)
            print(f"Sent: {path.name}")
        except Exception as e:
            print(f"Send failed: {e}")


def main():
    WATCH_FOLDER.mkdir(parents=True, exist_ok=True)
    print(f"Watching folder: {WATCH_FOLDER}")
    print(f"Sending to {HOST}:{PORT}")
    print(f" Using public key: {PUBLIC_KEY_PATH}")

    observer = Observer()
    observer.schedule(Handler(), str(WATCH_FOLDER), recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()


if __name__ == "__main__":
    main()
