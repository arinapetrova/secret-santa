# cryptography_app

Hello, this is my Cryptography final project.

Secret Santa App

(on command line) Sign in / sign up ("Do you have an account? y/n" if statement)

for sign up - ask for username and password, store this info in database (MongoDB?)

then somehow encrypt password (using hash+salt)

for sign in - enter username, enter password, authenticate using database. (in a loop, until successful)
Prompt for name, store in db

Menu options printed once logged in - Edit Wishlist, Join Group, Start Secret Santa, Delete Profile (optional)

- Edit Wishlist - prompt input until user says "done" (encrypt this list)

- Join Group - add name to database

- Start Secret Santa - Randomize assignments, print your person's wishlist and name

- Delete Profile - delete entry from database 

*Encryption ideas*: symmetrically encrypt the user's wishlist. Then, asymmetrically encrypt the symmetric key so that the wishlist can be accessed by the person someone is assigned. Symmetrically encrypt the user's assigned gift receiver name. 

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
