
# Secure Medical Image Sender

## Description
This module is the **sender side** of a secure medical image transmission system.  
It reads medical images, encrypts them using hybrid cryptography (RSA + ASCON), and securely transmits them to a receiver system over a network.

---

## Features
- Automatic image detection from folder
- Image conversion to byte format
- Random session key generation
- ASCON encryption of image data
- RSA encryption of session key
- Secure packet transmission via TCP socket
- Supports multiple images
