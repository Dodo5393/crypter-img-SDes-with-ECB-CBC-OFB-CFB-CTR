# crypter-img-SDes-with-ECB-CBC-OFB-CFB-CTR

- **Supports multiple image formats**: PBM, GIF, JPEG, PNG.

- **Color and grayscale image processing**.

- Various encryption modes

  :

  - ECB (Electronic Codebook)
  - CBC (Cipher Block Chaining)
  - OFB (Output Feedback)
  - CFB (Cipher Feedback)
  - CTR (Counter)

## Prerequisites

- Python 3.x
- Pillow (PIL) library
- argparse

Install the Pillow  and argparse library using pip:



```bash
pip install pillow argparse

```

## Usage

### Command Line Arguments

- **Path to the image file** that you want to encrypt.

### Example



```bash
python sdes_image_encryption.py path_to_plaintext_image.extension
```

## File Structure

- **sdes_image_encryption.py**: Main script containing the S-DES algorithm implementation and image encryption/decryption functions.
- **README.md**: This document.

## How to Run

1. **Ensure you have the Pillow library installed by executing**:

   

   ```bash
   pip install pillow
   ```
