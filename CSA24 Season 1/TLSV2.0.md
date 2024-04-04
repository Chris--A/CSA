# Challenge: TLSV2.0 *(CSA Season 1 2024)*

## Overview

The Diffie-Hellman Key Exchange (DHE) is a method of securely exchanging cryptographic keys over a public channel and is one of the foundational methods used for securing communications. The components involved in the process are:

| Component | Symbol | Description |
|-----------|--------|-------------|
| Generator | `g` | A publicly shared base number used in the exponentiation operations. It's chosen so that it has a large multiplicative order modulo \( p \). |
| Prime Modulus | `p` | A large prime number, publicly shared and used as the modulus for the arithmetic operations in the exchange. |
| Alice's Private Key | `a` | Alice's secret value, chosen randomly. It's never shared and is used to generate Alice's public key and the shared secret key. |
| Bob's Private Key | ` b` | Bob's secret value, chosen randomly. Like Alice's private key, it's never shared and is used to generate Bob's public key and the shared secret key. |
| Alice's Public Key | `A` | Calculated by Alice as `A = g^a mod p`. This value is shared with Bob over the public channel. |
| Bob's Public Key | ` B` | Calculated by Bob as `B = g^b mod p`. This value is shared with Alice over the public channel. |
| Shared Key | `s` | A secret key derived independently by both Alice and Bob using each other's public key and their own private key. For Alice: `s = B^a mod p`, and for Bob: `s = A^b mod p`. Both computations result in the same value `s`, which can then be used as a secret key for further encryption. |
| Key derivation function | `KDF` | The method used to compute the AES key from the shared key. |

Below is an excerpt of a capture I received, and I will base this write up on it. As interaction with the remote application is fairly trivial I will leave that out and focus on the decryption task. 
```
$> Hello. TLS version: TLSv2.0. My ciphers: TLS_DHE_WITH_AES_256_CBC_SHA256.
Hello. Change cipher spec to TLS_DHE_WITH_AES_256_CBC_SHA256.
KDF: SHA256. g: 272. p: 239. My DHE: 15
Hello finished.
$> My DHE: 10.
*** BEGIN ENCRYPTED MESSAGE ***
aqLdbgETxrINANYL8yylhcTy17zc8deNBcD8fevDCYylJvm89w26lSIRmx/HOtVaoi18w8zsNFQYWKD/xvF84w==
*** END ENCRYPTED MESSAGE ***
```

The data we can gather from this is:

| Symbol | Description |
|--------|-------------|
| `KDF` | SHA256 |
| `g` | 272 |
| `p` | 239 |
| `B` | 15 |
| `A` | 10 |

## Solution

The trick to successfully completing this challenge is to ensure you input correct values when grabbing the initial data (this was the part I got stuck on for a while). `A`/*My DHE* cannot be random, it must be derived from the values provided. We can proceed after receiving the first part:

```
$> Hello. TLS version: TLSv2.0. My ciphers: TLS_DHE_WITH_AES_256_CBC_SHA256.
Hello. Change cipher spec to TLS_DHE_WITH_AES_256_CBC_SHA256.
KDF: SHA256. g: 272. p: 239. My DHE: 15
Hello finished.
```

As shown in the overview, `A` is calculated as `A = g^a mod p`. As we do not currently have a value for a `a` one must be chosen (our random private key).  For this example I will use **85**. Substituting the symbols for values we get: `10 = 272 ^ 85 mod 239`. This can be verified with:

```python
g = 272
p = 239
a = 85   # My private key, could be anything
A = pow(g, a, p)

print(f"My shared key: {A}")
```
> My shared key: 10

Now we have a value for `A`, we can pass it to the application and retreive the message:

```
$> My DHE: 10.
*** BEGIN ENCRYPTED MESSAGE ***
aqLdbgETxrINANYL8yylhcTy17zc8deNBcD8fevDCYylJvm89w26lSIRmx/HOtVaoi18w8zsNFQYWKD/xvF84w==
*** END ENCRYPTED MESSAGE ***
```

Now we have almost everything we need to solve the problem. AES required an initialisation vector (IV) which we need to find, and AES256 has a 16 byte IV. Thankfully, placing the 16-byte IV at the start of the base64-encoded data is a common practice in symmetric encryption schemes, like AES. We can split the IV and ciphertext easily:

```python
raw = base64.b64decode('aqLdbgETxrINANYL8yylhcTy17zc8deNBcD8fevDCYylJvm89w26lSIRmx/HOtVaoi18w8zsNFQYWKD/xvF84w==')
iv = raw[:16]
ciphertext = raw[16:]
```

We then need to calculate the shared key. As we are *Alice*, our shared key will be derived from *Bob's* public key and our private key (`s = B^a mod p`):

```python
key = pow(B, a, p)
```

The last step is to convert the shared key to the AES key, which is done using the key derivation function. In this case it is SHA256.

```python
key_bytes = key.to_bytes((key.bit_length() + 7) // 8, 'big')
aes_key = SHA256.new(key_bytes).digest()
```

Adding 7 in the first line ensures that when the bit length is divided by 8, any remainder will result in an extra byte being added. This is a common technique used to round up to the nearest byte when converting bit lengths to byte lengths. Then the resulting bytes are hashed using SHA256 giving us the AES key.

To complete this write up, here is a working example which contains the decryption using all the values calculated above.

```python
'''
    Captured message

    $> Hello. TLS version: TLSv2.0. My ciphers: TLS_DHE_WITH_AES_256_CBC_SHA256.
    Hello. Change cipher spec to TLS_DHE_WITH_AES_256_CBC_SHA256.
    KDF: SHA256. g: 272. p: 239. My DHE: 15
    Hello finished.
    $> My DHE: 10.
    *** BEGIN ENCRYPTED MESSAGE ***
    aqLdbgETxrINANYL8yylhcTy17zc8deNBcD8fevDCYylJvm89w26lSIRmx/HOtVaoi18w8zsNFQYWKD/xvF84w==
    *** END ENCRYPTED MESSAGE ***
'''

import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

# DHE algo values provided, Key derivation function is SHA256
g = 272
p = 239
B = 15   # Remote DHE
a = 85   # My random private key
raw = base64.b64decode('aqLdbgETxrINANYL8yylhcTy17zc8deNBcD8fevDCYylJvm89w26lSIRmx/HOtVaoi18w8zsNFQYWKD/xvF84w==')

# IV for AES256 is 16 bytes, and is typically stored as prefix to message
iv = raw[:16]
ciphertext = raw[16:]

#calculate key
key = pow(B, a, p)
key_bytes = key.to_bytes((key.bit_length() + 7) // 8, 'big')
aes_key = SHA256.new(key_bytes).digest()

#decrypt data
plaintext = AES.new(aes_key, AES.MODE_CBC, iv).decrypt(ciphertext)

print(f"Decrypted data: {plaintext}")
```

The decrypted flag is:

### `FLAG{Diff1e&h3llM@n.w0uld-b3.pr0ud}`

----
## Bonus points

As the prime numbers used with this task are fairly trivial the key is very quick to brute force. Here is a different capture decrypted without any calculations (`A` is completely random and I do not know `a`):

```python
'''
$> Hello. TLS version: TLSv2.0. My ciphers: TLS_DHE_WITH_AES_256_CBC_SHA256.
Hello. Change cipher spec to TLS_DHE_WITH_AES_256_CBC_SHA256.
KDF: SHA256. g: 59. p: 251. My DHE: 219
Hello finished.
$> My DHE: 1.
*** BEGIN ENCRYPTED MESSAGE ***
tgCeTX/6+YWlPz0HjwNy1KAz93D45ffh9KJ89RHQc4a5kxi98Qa6wb1vvDqUcrA9xOXS6RP17xRUkH030L/FUQ==
*** END ENCRYPTED MESSAGE ***
'''
import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

raw = base64.b64decode('tgCeTX/6+YWlPz0HjwNy1KAz93D45ffh9KJ89RHQc4a5kxi98Qa6wb1vvDqUcrA9xOXS6RP17xRUkH030L/FUQ==')
iv = raw[:16]
ciphertext = raw[16:]

for i in range(0, 101):
    shared_key = i
    shared_key_bytes = shared_key.to_bytes((shared_key.bit_length() + 7) // 8, 'big')
    aes_key = SHA256.new(shared_key_bytes).digest()
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    
    if plaintext.startswith(b'FLAG'):
        print(f"Found with key {i} : {plaintext}")
        break
```


