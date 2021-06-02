# Ξ Aether

A general-purpose Ethereum C library. This library is an on-going work-in-progress, and the API should not be considered stable.

## Features

* Private key generation
* Public Key, Address, and EIP-55 Address from private key
* Transaction creation and signing
* RLP-encoding implementation
* Access to cryptographic primitives (secp256k1 `ECDSAPUBKEY`, `ECDSASIGN`, keccak256 hashing)

## Example Usage

Importing a private key, creating and signing a transaction, sending 1 ETH with a gas price of 1 GWei, with no data:
```c
#include <aether/secp256k1.h>
#include <aether/tx.h>
#include <aether/vector/vector-uchar.h>
#include <secp256k1.h>

//Importing a secret key from a string literal
aether_secp256k1_seckey sk;
aether_secp256k1_seckey_import(&sk, ETH_PRV_KEY);

//Initializing a transaction with the proper data
struct aether_eth_tx tx;
aether_eth_tx_init(&tx, "0", "100000000", "21000", "F7FE578C81788A551E6C3EFA54501F463CE26AF7", "1000000000000000000", "", "1");

//Create the proper secp256k1 context pointer
secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

//Initialize a dynamically-sized buffer of bytes to hold our signed RLP-encoded tx
struct aether_vector_uchar tx_sig;
aether_vector_uchar_init(&tx_sig);

//Finally, sign!
aether_eth_tx_sign(&tx_sig, &tx, &sk, ctx);

aether_eth_tx_deinit(&tx);
aether_vector_uchar_deinit(&tx_sig);
secp256k1_context_destroy(ctx);
```

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
