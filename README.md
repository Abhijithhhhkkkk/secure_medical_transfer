# Secure Medical Transfer (Sender + Receiver)

## Overview
**Secure Medical Transfer** is a combined project that securely transmits medical images from a **Sender** system to a **Receiver** system using **hybrid cryptography (RSA + ASCON)**.

**Sender** encrypts medical image data using **ASCON (AEAD)** and encrypts the session key using **RSA public key**, then transmits the packet over TCP.
 **Receiver** decrypts the RSA-encrypted session key using **RSA private key**, decrypts the image using **ASCON**, verifies the authentication tag, stores the decrypted image, and displays it using a **Flask web dashboard**.



## Security Model

### RSA (Asymmetric)
 Used only to protect the **session key**
 `public.pem` is shared with sender
 `private.pem` stays only on receiver

### ASCON (Lightweight AEAD)
 Encrypts medical image bytes
 Provides **confidentiality + integrity + authentication**
Uses a **nonce** and **authentication tag** to prevent tampering / replay



##  Requirements

Install dependencies on both sender and receiver machines

## Expected Output

Encrypted packets sent over the network

Receiver decrypts and verifies authentication tag

Decrypted image saved to receiver/static/images/

Image visible on Flask dashboard
