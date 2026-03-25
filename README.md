# cryptography_app

Hello, this is my Cryptography final project.

Secret Santa App


requirements:
1. Proper Password Storage
2. Encrypt and authenticate the data that needs to be protected
3. Digital Signature - for certain data, and extract it from this data, and verify the digital signature
    need to create a pair of asymmetric keys for this 

| Action                 | Crypto used                          | Description                                                                    |
| ---------------------- | ------------------------------------ | ------------------------------------------------------------------------------ |
| **Sign up**            | Argon2id (hash) + Ed25519 keypair    | Hash password; generate keys; encrypt private key with user’s AES key          |
| **Sign in**            | Argon2id verify + AES key derivation | Verify password, derive AES key to decrypt private key and wishlist            |
| **Edit Wishlist**      | AES-GCM                              | Encrypt list with AES key before DB write                                      |
| **Join Group**         | none / optional                      | Group list can be plaintext unless you want to sign membership                 |
| **Start Secret Santa** | AES-GCM + Ed25519 signatures         | Organizer encrypts & signs assignments; writes encrypted, signed results to DB |
| **View Assignment**    | AES-GCM decrypt + verify signature   | User decrypts assignment with their key, verifies the organizer’s signature    |
| **Delete Profile**     | —                                    | Remove entry from DB                                                           |
