# Ξ Aether

A general-purpose Ethereum C library. This library is an on-going work-in-progress, and the API should not be considered stable.

`<aether/eth.h>`, `<aether/rlp.h>`, and `<aether/tx.h>` make up the headers most intended to be user-facing.

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

## Testing

Running `make` in the [`./test`](test) directory will build and execute all tests. Catch2 is used as the unit testing framework.

Note that tests working with signing transactions will require a private key. Create `config.h` within the `./test/include` directory with the macro `AETHER_ETH_TEST_PRV_KEY` set to a valid private key as a string literal.

## Future Implementations/Work

* secp256k1 `ECDSARECOVER` cryptographic primtive
* Moving to a proper build system (i.e. Meson)

## License
This library has been licensed under the GNU Lesser General Public License v2.1.
