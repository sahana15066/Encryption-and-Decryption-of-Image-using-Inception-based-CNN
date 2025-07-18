# Encryption-and-Decryption-of-Image-using-Inception-based-CNN
import cv2
import numpy as np
import os
#step 1: Pre-processing
import cv2
import numpy as np
import matplotlib.pyplot as plt

def load_and_preprocess_image(image_path):
    # Load image
    image = cv2.imread(image_path)
    
    # Convert to grayscale
    gray_image = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    
    # Resize image
    resized_image = cv2.resize(gray_image, (128, 128))  # Example size
    return resized_image

image_path = 'peppers.jpg'
fingerprint_image = load_and_preprocess_image(image_path)

# Display the image
plt.imshow(fingerprint_image, cmap='gray')
plt.title('Preprocessed Image')
plt.axis('off')
plt.show()
#Step 2: Fingerprint Feature Extraction using a Lightweight CNN
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv2D, MaxPooling2D, Flatten, Dense

def create_lightweight_cnn():
    model = Sequential([
        Conv2D(32, (3, 3), activation='relu', input_shape=(128, 128, 1)),
        MaxPooling2D(pool_size=(2, 2)),
        Conv2D(64, (3, 3), activation='relu'),
        MaxPooling2D(pool_size=(2, 2)),
        Flatten(),
        Dense(128, activation='relu'),
        Dense(64, activation='relu'),  # Feature vector size
    ])
    return model

# Create and compile the model
cnn_model = create_lightweight_cnn()
cnn_model.compile(optimizer='adam', loss='mean_squared_error')

# Reshape and normalize the fingerprint image for CNN
fingerprint_image_expanded = np.expand_dims(fingerprint_image, axis=-1) / 255.0
fingerprint_image_expanded = np.expand_dims(fingerprint_image_expanded, axis=0)

# Extract features
features = cnn_model.predict(fingerprint_image_expanded)
print("Extracted Features Shape:", features.shape)
#Step 3: Key Generation and ECC
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import NoEncryption

def generate_keys():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    # Serialize keys for storage/transmission
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=NoEncryption()  # Specify no encryption for simplicity
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    return private_bytes, public_bytes

private_key, public_key = generate_keys()
print("Private Key:", private_key)
print("Public Key:", public_key)

#Step 4: Encryption and Decryption of Fingerprint Features
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def derive_key(private_key, public_key):
    # Combine keys to create a shared secret
    shared_secret = private_key + public_key  # This is a simple example
    kdf = Scrypt(
        salt=os.urandom(16),
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    key = kdf.derive(shared_secret)
    return key

def encrypt(features, key):
    iv = os.urandom(16)  # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(features.tobytes()) + encryptor.finalize()
    return iv, encrypted

def decrypt(iv, encrypted, key):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted) + decryptor.finalize()
    return np.frombuffer(decrypted, dtype=np.float32).reshape(features.shape)

# Derive a key from ECC keys
key = derive_key(private_key, public_key)

# Encrypt and decrypt features
iv, encrypted_features = encrypt(features, key)
decrypted_features = decrypt(iv, encrypted_features, key)

#Step 5: Display of Encrypted and Decrypted Images
import numpy as np
import matplotlib.pyplot as plt
from PIL import Image
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Load the image
img = Image.open('peppers.jpg')
img_array = np.array(img)

# Ensure the image is grayscale for simplicity
if len(img_array.shape) == 3:
    img_array = np.mean(img_array, axis=2).astype(np.uint8)

# Generate ECC key pair
private_key = x25519.X25519PrivateKey.generate()
public_key = private_key.public_key()

# Serialize public key for encryption
public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

# Derive a symmetric key from the ECC public key
def derive_key(public_key_bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'some_salt',  # Use a proper salt in production
        iterations=100000,  # Number of iterations for key derivation
        backend=default_backend()
    )
    derived_key = kdf.derive(public_key_bytes)
    return derived_key

# Ensure key length matches image data length
def adjust_key_length(derived_key, length):
    # Repeat the key to match the image data length
    key_repeated = np.frombuffer(derived_key, dtype=np.uint8)
    key_repeated = np.tile(key_repeated, (length // len(derived_key) + 1))[:length]
    return key_repeated

# XOR encryption function
def xor_operation(data, key):
    return np.array([(byte ^ key[i % len(key)]) for i, byte in enumerate(data)], dtype=np.uint8)

# ECC encryption function
def encrypt(img_array, derived_key):
    flattened_image = img_array.flatten().astype(np.uint8)
    key_repeated = adjust_key_length(derived_key, len(flattened_image))
    encrypted_image = xor_operation(flattened_image, key_repeated)
    return encrypted_image.reshape(img_array.shape)

# ECC decryption function
def decrypt(encrypted_img, derived_key):
    flattened_image = encrypted_img.flatten().astype(np.uint8)
    key_repeated = adjust_key_length(derived_key, len(flattened_image))
    decrypted_image = xor_operation(flattened_image, key_repeated)
    return decrypted_image.reshape(encrypted_img.shape)

# Derive a symmetric key
derived_key = derive_key(public_key_bytes)

# Encrypt the image
encrypted_img = encrypt(img_array, derived_key)
encrypted_img_pil = Image.fromarray(encrypted_img.astype(np.uint8))

# Decrypt the image
decrypted_img = decrypt(np.array(encrypted_img_pil), derived_key)
decrypted_img_pil = Image.fromarray(decrypted_img.astype(np.uint8))

# Plot the results
fig, axs = plt.subplots(1, 3, figsize=(15, 5))
axs[0].imshow(img, cmap='gray')
axs[0].set_title('Original Image')
axs[1].imshow(encrypted_img_pil, cmap='gray')
axs[1].set_title('Encrypted Image')
axs[2].imshow(decrypted_img_pil, cmap='gray')
axs[2].set_title('Decrypted Image')
plt.show()

//Output:
import cv2
import numpy as np
import os
#step 1: Pre-processing
import cv2
import numpy as np
import matplotlib.pyplot as plt

def load_and_preprocess_image(image_path):
    # Load image
    image = cv2.imread(image_path)
    
    # Convert to grayscale
    gray_image = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    
    # Resize image
    resized_image = cv2.resize(gray_image, (128, 128))  # Example size
    return resized_image

image_path = 'peppers.jpg'
fingerprint_image = load_and_preprocess_image(image_path)

# Display the image
plt.imshow(fingerprint_image, cmap='gray')
plt.title('Preprocessed Image')
plt.axis('off')
plt.show()
#Step 2: Fingerprint Feature Extraction using a Lightweight CNN
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv2D, MaxPooling2D, Flatten, Dense

def create_lightweight_cnn():
    model = Sequential([
        Conv2D(32, (3, 3), activation='relu', input_shape=(128, 128, 1)),
        MaxPooling2D(pool_size=(2, 2)),
        Conv2D(64, (3, 3), activation='relu'),
        MaxPooling2D(pool_size=(2, 2)),
        Flatten(),
        Dense(128, activation='relu'),
        Dense(64, activation='relu'),  # Feature vector size
    ])
    return model

# Create and compile the model
cnn_model = create_lightweight_cnn()
cnn_model.compile(optimizer='adam', loss='mean_squared_error')

# Reshape and normalize the fingerprint image for CNN
fingerprint_image_expanded = np.expand_dims(fingerprint_image, axis=-1) / 255.0
fingerprint_image_expanded = np.expand_dims(fingerprint_image_expanded, axis=0)

# Extract features
features = cnn_model.predict(fingerprint_image_expanded)
print("Extracted Features Shape:", features.shape)
#Step 3: Key Generation and ECC
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import NoEncryption

def generate_keys():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    # Serialize keys for storage/transmission
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=NoEncryption()  # Specify no encryption for simplicity
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    return private_bytes, public_bytes

private_key, public_key = generate_keys()
print("Private Key:", private_key)
print("Public Key:", public_key)

#Step 4: Encryption and Decryption of Fingerprint Features
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def derive_key(private_key, public_key):
    # Combine keys to create a shared secret
    shared_secret = private_key + public_key  # This is a simple example
    kdf = Scrypt(
        salt=os.urandom(16),
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    key = kdf.derive(shared_secret)
    return key

def encrypt(features, key):
    iv = os.urandom(16)  # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(features.tobytes()) + encryptor.finalize()
    return iv, encrypted

def decrypt(iv, encrypted, key):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted) + decryptor.finalize()
    return np.frombuffer(decrypted, dtype=np.float32).reshape(features.shape)

# Derive a key from ECC keys
key = derive_key(private_key, public_key)

# Encrypt and decrypt features
iv, encrypted_features = encrypt(features, key)
decrypted_features = decrypt(iv, encrypted_features, key)

#Step 5: Display of Encrypted and Decrypted Images
import numpy as np
import matplotlib.pyplot as plt
from PIL import Image
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Load the image
img = Image.open('peppers.jpg')
img_array = np.array(img)

# Ensure the image is grayscale for simplicity
if len(img_array.shape) == 3:
    img_array = np.mean(img_array, axis=2).astype(np.uint8)

# Generate ECC key pair
private_key = x25519.X25519PrivateKey.generate()
public_key = private_key.public_key()

# Serialize public key for encryption
public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

# Derive a symmetric key from the ECC public key
def derive_key(public_key_bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'some_salt',  # Use a proper salt in production
        iterations=100000,  # Number of iterations for key derivation
        backend=default_backend()
    )
    derived_key = kdf.derive(public_key_bytes)
    return derived_key

# Ensure key length matches image data length
def adjust_key_length(derived_key, length):
    # Repeat the key to match the image data length
    key_repeated = np.frombuffer(derived_key, dtype=np.uint8)
    key_repeated = np.tile(key_repeated, (length // len(derived_key) + 1))[:length]
    return key_repeated

# XOR encryption function
def xor_operation(data, key):
    return np.array([(byte ^ key[i % len(key)]) for i, byte in enumerate(data)], dtype=np.uint8)

# ECC encryption function
def encrypt(img_array, derived_key):
    flattened_image = img_array.flatten().astype(np.uint8)
    key_repeated = adjust_key_length(derived_key, len(flattened_image))
    encrypted_image = xor_operation(flattened_image, key_repeated)
    return encrypted_image.reshape(img_array.shape)

# ECC decryption function
def decrypt(encrypted_img, derived_key):
    flattened_image = encrypted_img.flatten().astype(np.uint8)
    key_repeated = adjust_key_length(derived_key, len(flattened_image))
    decrypted_image = xor_operation(flattened_image, key_repeated)
    return decrypted_image.reshape(encrypted_img.shape)

# Derive a symmetric key
derived_key = derive_key(public_key_bytes)

# Encrypt the image
encrypted_img = encrypt(img_array, derived_key)
encrypted_img_pil = Image.fromarray(encrypted_img.astype(np.uint8))

# Decrypt the image
decrypted_img = decrypt(np.array(encrypted_img_pil), derived_key)
decrypted_img_pil = Image.fromarray(decrypted_img.astype(np.uint8))

# Plot the results
"C:\Users\Asus\Downloads\pic.jpg"
