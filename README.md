# Ξ Aether

A general-purpose Ethereum C library. This library is an on-going work-in-progress, and the API should not be considered stable.

## Features

* Private key generation
* Public Key, Address, and EIP-55 Address from private key
* Transaction creation and signing
* RLP-encoding implementation
* Access to cryptographic primitives (secp256k1 `ECDSAPUBKEY`, `ECDSASIGN`, keccak256 hashing)

## Installation

### Unix-like OS (e.g. Linux, BSD, Mac OS)
Aether currently requires `libsecp256k1` and `libgmp` as dependencies. On Ubuntu, they may be installed by running:
```
sudo apt install libsecp256k1-dev
sudo apt install libgmp-dev
```

## Future Implementations/Work

* secp256k1 `ECDSARECOVER` cryptographic primtive
* Moving to a proper build system (i.e. Meson)
* Correcting header organization

## License
This library has been licensed under the GNU Lesser General Public License v2.1.
