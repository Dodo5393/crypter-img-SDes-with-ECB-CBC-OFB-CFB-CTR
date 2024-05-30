import numpy as np
from PIL import Image
import argparse

P10 = [2, 4, 1, 6, 3, 9, 0, 8, 7, 5]
P8 = [5, 2, 6, 3, 7, 4, 9, 8]
P4 = [1, 3, 2, 0]
IP = [1, 5, 2, 0, 3, 7, 4, 6]
EP = [3, 0, 1, 2, 1, 2, 3, 0]
IP_inv = [3, 0, 2, 4, 6, 1, 7, 5]

S1 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]

S2 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]


def permute(bits, table):
    return "".join(bits[i] for i in table)


def xor(bits1, bits2):
    return "".join("1" if b1 != b2 else "0" for b1, b2 in zip(bits1, bits2))


def sbox_lookup(bits, sbox):
    row = int(bits[0] + bits[3], 2)
    col = int(bits[1:3], 2)
    return "{0:02b}".format(sbox[row][col])


def round_function(bits, key):
    expanded_bits = permute(bits, EP)
    xored = xor(expanded_bits, key)
    sbox_out = sbox_lookup(xored[:4], S1) + sbox_lookup(xored[4:], S2)
    return permute(sbox_out, P4)


def generate_keys(key):
    key = permute(key, P10)
    left_key = key[:5]
    right_key = key[5:]
    left_key = left_key[1:] + left_key[:1]
    right_key = right_key[1:] + right_key[:1]
    key1 = permute(left_key + right_key, P8)
    left_key = left_key[2:] + left_key[:2]
    right_key = right_key[2:] + right_key[:2]
    key2 = permute(left_key + right_key, P8)
    return key1, key2


def sdes_encrypt(plaintext, key):
    key1, key2 = generate_keys(key)
    permuted_plaintext = permute(plaintext, IP)
    round1_out = round_function(permuted_plaintext[4:], key1)
    round1_xor = xor(permuted_plaintext[:4], round1_out)
    permuted_plaintext = permuted_plaintext[4:] + round1_xor
    round2_out = round_function(permuted_plaintext[4:], key2)
    round2_xor = xor(permuted_plaintext[:4], round2_out)
    ciphertext = permute(round2_xor + permuted_plaintext[4:], IP_inv)
    return ciphertext


def sdes_decrypt(ciphertext, key):
    key1, key2 = generate_keys(key)
    permuted_ciphertext = permute(ciphertext, IP)
    round2_out = round_function(permuted_ciphertext[4:], key2)
    round2_xor = xor(permuted_ciphertext[:4], round2_out)
    permuted_ciphertext = permuted_ciphertext[4:] + round2_xor
    round1_out = round_function(permuted_ciphertext[4:], key1)
    round1_xor = xor(permuted_ciphertext[:4], round1_out)
    plaintext = permute(round1_xor + permuted_ciphertext[4:], IP_inv)
    return plaintext


def convert_byte_to_bitstring(byte):
    return format(byte, "08b")


def convert_bitstring_to_byte(bitstring):
    return int(bitstring, 2)


def process_image_channels(image):
    # Split image into R, G, B channels
    r, g, b = image.split()

    # Convert channels to numpy arrays for easier processing
    r = np.array(r)
    g = np.array(g)
    b = np.array(b)

    return r.flatten(), g.flatten(), b.flatten(), r.shape


def reconstruct_image_from_channels(r_channel, g_channel, b_channel, shape):
    r = np.array(r_channel, dtype=np.uint8).reshape(shape)
    g = np.array(g_channel, dtype=np.uint8).reshape(shape)
    b = np.array(b_channel, dtype=np.uint8).reshape(shape)

    return Image.merge(
        "RGB", (Image.fromarray(r), Image.fromarray(g), Image.fromarray(b))
    )


def int_to_bitstring(num, length):
    return format(num, "0{}b".format(length))


def encrypt_channels(channels, key, mode, iv=None, nonce=None):
    encrypted_channels = []
    for channel in channels:
        bitstrings = [convert_byte_to_bitstring(byte) for byte in channel]

        if mode == "ECB":
            processed_bitstrings = [sdes_encrypt(bits, key) for bits in bitstrings]
        elif mode == "CBC":
            processed_bitstrings = []
            prev_block = iv
            for bits in bitstrings:
                # Encryption
                xor_bits = xor(bits, prev_block)
                encrypted_bits = sdes_encrypt(xor_bits, key)
                processed_bitstrings.append(encrypted_bits)
                prev_block = encrypted_bits
        elif mode == "OFB":
            processed_bitstrings = []
            feedback = iv
            for bits in bitstrings:
                feedback = sdes_encrypt(feedback, key)
                processed_bitstrings.append(xor(feedback, bits))
        elif mode == "CFB":
            processed_bitstrings = []
            prev_block = iv
            for bits in bitstrings:
                encrypted_feedback = sdes_encrypt(prev_block, key)
                cipher_bits = xor(encrypted_feedback, bits)
                processed_bitstrings.append(cipher_bits)
                prev_block = cipher_bits

        elif mode == "CTR":
            processed_bitstrings = []
            counter = 0
            for bits in bitstrings:
                counter_bits = nonce + int_to_bitstring(
                    counter, 8
                )  # assuming 8-bit counter
                encrypted_counter = sdes_encrypt(counter_bits, key)
                processed_bitstrings.append(xor(encrypted_counter, bits))
                counter += 1

        processed_channel = [
            convert_bitstring_to_byte(bits) for bits in processed_bitstrings
        ]
        encrypted_channels.append(processed_channel)
    return encrypted_channels


def main():
    key = "0111111101"  # Example key
    parser = argparse.ArgumentParser(description="Encrypt images using S-DES.")
    parser.add_argument("image_path", type=str, help="Path to the input image")
    args = parser.parse_args()
    plaintext_image_path = args.image_path
    iv = "10101010"  # Example IV for CBC
    nonce = "11001100"  # Example nonce for CTR

    # Open image and ensure it is RGB
    plaintext_image = Image.open(plaintext_image_path).convert("RGB")

    # Process the image into its R, G, and B channels
    r_channel, g_channel, b_channel, shape = process_image_channels(plaintext_image)

    # Encrypt the image using ECB mode
    ecb_r, ecb_g, ecb_b = encrypt_channels(
        [r_channel, g_channel, b_channel], key, mode="ECB"
    )
    ecb_encrypted_image = reconstruct_image_from_channels(ecb_r, ecb_g, ecb_b, shape)
    ecb_encrypted_image.save("ecb_encrypted_image.png")

    # Encrypt the image using CBC mode with the IV
    cbc_r, cbc_g, cbc_b = encrypt_channels(
        [r_channel, g_channel, b_channel], key, mode="CBC", iv=iv
    )
    cbc_encrypted_image = reconstruct_image_from_channels(cbc_r, cbc_g, cbc_b, shape)
    cbc_encrypted_image.save("cbc_encrypted_image.png")

    # Encrypt the image using OFB mode with the IV
    ofb_r, ofb_g, ofb_b = encrypt_channels(
        [r_channel, g_channel, b_channel], key, mode="OFB", iv=iv
    )
    ofb_encrypted_image = reconstruct_image_from_channels(ofb_r, ofb_g, ofb_b, shape)
    ofb_encrypted_image.save("ofb_encrypted_image.png")

    # Encrypt the image using CFB mode with the IV
    cfb_r, cfb_g, cfb_b = encrypt_channels(
        [r_channel, g_channel, b_channel], key, mode="CFB", iv=iv
    )
    cfb_encrypted_image = reconstruct_image_from_channels(cfb_r, cfb_g, cfb_b, shape)
    cfb_encrypted_image.save("cfb_encrypted_image.png")

    ctr_r, ctr_g, ctr_b = encrypt_channels(
        [r_channel, g_channel, b_channel], key, mode="CTR", nonce=nonce
    )
    ctr_encrypted_image = reconstruct_image_from_channels(ctr_r, ctr_g, ctr_b, shape)
    ctr_encrypted_image.save("ctr_encrypted_image.png")


if __name__ == "__main__":
    main()
