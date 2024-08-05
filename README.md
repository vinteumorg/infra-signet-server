# Signet Server

The included script [signet-setup.py](./signet-setup.py) needs to be run by the administrator on a publicly reachable server to start the game.

The script requires a local installation of Bitcoin Core since it consumes the test framework as a library.

Usage: `python signet-setup.py <path/to/bitcoin> <path/to/student/files> <path/for/bitcoin/datadir>`

`<path/to/bitcoin>`: (required) Path to local installation of Bitcoin Core repository

`<path/to/student/files>`: (optional, default `./config`) Destination for student bitcoin.conf and wallet descriptors

`<path/for/bitcoin/datadir>`: (optional, default is `os.tmpdir()`) Data directory for the signet full node

The script runs the signet full node, creates all the wallets and continues mining blocks forever. It should never be killed, but the node can always be restarted by using `-datadir=<path/for/bitcoin/datadir>`

## Credits

This is [forked](https://github.com/chaincodelabs/signet-wallet-project) from the work of [Matthew Zipkin](https://github.com/chaincodelabs/signet-wallet-project) for Chaincode Labs.
