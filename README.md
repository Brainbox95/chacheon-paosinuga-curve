
Overview
This repository contains the implementation of the ChaCheon signature scheme integrated with a custom elliptic curve, the Paosinuga Curve. 
The project is designed to provide a secure and efficient framework for cryptographic operations using Python. It focuses on leveraging elliptic curve cryptography (ECC) for digital signatures and secure message encryption.

Implemented Components
Paosinuga Curve: A custom elliptic curve defined with new parameters for cryptographic operations. Includes methods for point addition, scalar multiplication, and other essential elliptic curve functions.
ChaCheon Signature Scheme: Implements the ChaCheon signature scheme for secure signing and verification of messages, enhancing security with elliptic curve cryptography.



Key Features
Custom Elliptic Curve Implementation: paosinuga_curve.py contains the Paosinuga Curve with methods for basic elliptic curve operations, adapted to the new parameters.

ChaCheon Integration: chacheon.py implements the ChaCheon signature scheme, enabling secure signing and verification using the Paosinuga Curve.

Secure Cloud Transfer Application: main.py provides a complete application for secure message transfer, integrating both the ChaCheon scheme and Paosinuga Curve. Includes functionality for user registration, message encryption, and decryption.




How to Use
Clone the Repository:
git clone https://github.com/Brainbox/chacheon-paosinuga-curve.git
cd chacheon-paosinuga-curve



Run the Application:
Python3 main.py
Follow the prompts to register users, send messages, and read messages.


Results
The repository showcases the integration of ChaCheon and Paosinuga Curve for secure communication. The application allows users to send encrypted messages with multi-layered security, including elliptic curve-based digital signatures and AES encryption.


Contribution
Contributions to improve the implementation, add new features, or expand the cryptographic analysis are welcome. Please fork the repository and submit pull requests.


License
This project is licensed under the MIT License - see the LICENSE file for details.



References
ChaCheon, C. (2021). ChaCheon Signature Scheme. Online Source
Elliptic Curve Cryptography. Wikipedia
PyCryptodome Documentation. PyCryptodome
