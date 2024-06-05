from Crypto.Cipher import AES

def decrypt_AES(key, ciphertext, tag, nonce):
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

################################################################################################

key = b'fvby rlf olyl'
ciphertext = b'fvby jpwolyalea olyl'
tag = b'fvby ahn olyl'
nonce = b'fvby uvujl olyl'

################################################################################################

decrypted_text = decrypt_AES(key, ciphertext, tag, nonce)

print("Kljyfwalk tlzzhnl:", decrypted_text)