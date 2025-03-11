# Helper function to permute bits using a given table
def permute(bits, table):
    return ''.join(bits[i - 1] for i in table)

# Helper function to expand 32 bits to 48 bits using the E-bit selection table
def expand(bits):
    E = [
        32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
    ]
    return permute(bits, E)

# Helper function to XOR two bit strings
def xor(bits1, bits2):
    return ''.join(str(int(b1) ^ int(b2)) for b1, b2 in zip(bits1, bits2))

# Helper function to substitute 6-bit chunks using S-boxes
def substitute(bits):
    S_BOXES = [
        # S1
        [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
        # S2
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
        # S3
        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
        # S4
        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
        # S5
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
        # S6
        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
        # S7
        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
        # S8
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
    ]
    result = ''
    for i in range(8):
        chunk = bits[i * 6:(i + 1) * 6]
        row = int(chunk[0] + chunk[5], 2)
        col = int(chunk[1:5], 2)
        val = S_BOXES[i][row][col]
        result += f"{val:04b}"
    return result

# Helper function to permute using the P-box
def pbox_permute(bits):
    P = [
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
    ]
    return permute(bits, P)

def des_round(left, right, round_key):
    # Expand the right half to 48 bits
    expanded = expand(right)
    # XOR with the round key
    xored = xor(expanded, round_key)
    # Substitute using S-boxes
    substituted = substitute(xored)
    # Permute using the P-box
    permuted = pbox_permute(substituted)
    # XOR with the left half
    new_right = xor(left, permuted)
    return right, new_right

def des_encrypt(block, round_keys):
    # Initial Permutation (IP)
    IP = [
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
    ]
    block = permute(block, IP)

    # Split into left and right halves
    left, right = block[:32], block[32:]

    # Perform 16 rounds
    for i in range(16):
        left, right = des_round(left, right, round_keys[i])

    # Final swap and permutation
    combined = right + left
    FP = [
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
    ]
    ciphertext = permute(combined, FP)
    return ciphertext


# ADDING THE CBC FUNCTION


def cbc_encrypt(plaintext, round_keys, iv):
    # Convert plaintext to binary
    binary_plaintext = ''.join(f"{ord(c):08b}" for c in plaintext)

    # Split into 64-bit blocks
    blocks = [binary_plaintext[i:i + 64] for i in range(0, len(binary_plaintext), 64)]

    # Pad the last block if necessary
    if len(blocks[-1]) < 64:
        blocks[-1] = blocks[-1].ljust(64, '0')

    # Encrypt each block in CBC mode
    ciphertext = ''
    previous_block = iv
    for block in blocks:
        # XOR with the previous ciphertext block (or IV for the first block)
        xored = xor(block, previous_block)
        # Encrypt using DES
        encrypted = des_encrypt(xored, round_keys)
        ciphertext += encrypted
        previous_block = encrypted

    return ciphertext

# Sample plaintext, IV, and round keys
plaintext = "Hello DES in CBC Mode"
iv = '0' * 64  # 64-bit IV (all zeros for simplicity)
round_keys = ["010101010101010101010101010101010101010101010101"] * 16  # Sample round keys

# Encrypt using CBC mode
ciphertext = cbc_encrypt(plaintext, round_keys, iv)
print("Ciphertext:", ciphertext)



## decryption method to test
# def binary_to_text(binary_str):
#     """
#     Converts a binary string to a readable ASCII string.
#     Arguments:
#         binary_str (str): Binary string (e.g., "01000001" for 'A')
#     Returns:
#         str: Human-readable string
#     """
#     # Ensure the binary string length is a multiple of 8 (1 byte = 8 bits)
#     n = 8
#     binary_str = binary_str[:len(binary_str) - len(binary_str) % n]  # Trim excess if necessary
#     text = ''.join(chr(int(binary_str[i:i + n], 2)) for i in range(0, len(binary_str), n))  # Convert
#     return text
#
#
# def des_decrypt(ciphertext, round_keys):
#     """
#     Decrypts a 64-bit DES ciphertext using the given 16 round keys.
#     Arguments:
#         ciphertext (str): 64-bit binary ciphertext to decrypt
#         round_keys (list): List of 16 48-bit binary round keys
#     Returns:
#         plaintext (str): Decrypted 64-bit binary plaintext
#     """
#     # Reverse the order of the round keys for decryption
#     reversed_keys = round_keys[::-1]
#
#     # Treat decryption as encryption but with reversed keys
#     plaintext = des_encrypt(ciphertext, reversed_keys)
#
#     return plaintext
#
# def cbc_decrypt(ciphertext, round_keys, iv):
#     """
#     Decrypts a ciphertext using DES in CBC mode.
#
#     Arguments:
#         ciphertext (str): Binary ciphertext string to decrypt.
#         round_keys (list): List of 16 binary round keys used for DES decryption.
#         iv (str): The initialization vector (64-bit binary string).
#
#     Returns:
#         str: The final plaintext in human-readable format.
#     """
#
#     def xor(a, b):
#         """Perform bitwise XOR between two binary strings."""
#         return ''.join(str(int(x) ^ int(y)) for x, y in zip(a, b))
#
#     def binary_to_text(binary_str):
#         """Convert a binary string to human-readable text."""
#         n = 8  # 8 bits per character
#         return ''.join(chr(int(binary_str[i:i + n], 2)) for i in range(0, len(binary_str), n))
#
#     block_size = 64  # DES works on 64-bit blocks
#     blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
#
#     decrypted_binary = []
#     previous_block = iv  # Start with the IV for CBC mode
#
#     # Process each ciphertext block
#     for block in blocks:
#         # Decrypt the current block using DES
#         decrypted_block = des_decrypt(block, round_keys)  # Already decrypts binary data
#
#         # XOR the decrypted block with the previous ciphertext block (or IV for the first block)
#         plaintext_binary = xor(decrypted_block, previous_block)
#
#         decrypted_binary.append(plaintext_binary)
#
#         # Update the previous block (current ciphertext block becomes the previous block)
#         previous_block = block
#
#     # Combine the decrypted blocks
#     decrypted_binary_str = ''.join(decrypted_binary)
#
#     # Convert binary to human-readable text
#     plaintext = binary_to_text(decrypted_binary_str)
#
#     return plaintext
#
#
# # Test the decryption functionality
# if __name__ == "__main__":
#     # Provided test data
#     ciphertext = "011001011110111001011011101100100111010100010011111100110101001001100101001010101011010011101111100011000110110100111100100111001100011100101111010100101110001110100011111111101011110110100111"
#     iv = '0' * 64  # Initialization vector (all zeros for simplicity)
#     round_keys = ["010101010101010101010101010101010101010101010101"] * 16  # Example round keys
#
#     # Decrypt the ciphertext
#     decrypted_message = cbc_decrypt(ciphertext, round_keys, iv)
#     print("Decrypted Message:", decrypted_message)
#
