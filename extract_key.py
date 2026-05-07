from ipv8.keyvault.crypto import default_eccrypto

# 1. Load the private key from your .pem file
with open("my_key.pem", "rb") as key_file:
    # This returns a private key object (usually LibNaCLSK or similar)
    private_key = default_eccrypto.key_from_private_bin(key_file.read())

# 2. Access the corresponding public key object
public_key = private_key.pub()

# 3. Get the binary or hex representation
public_key_bin = public_key.key_to_bin()
public_key_hex = public_key_bin.hex()

print(f"Public Key (Hex): {public_key_hex}")