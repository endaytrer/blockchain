# Blockchain

### How to run

```bash
git clone https://github.com/endaytrer/blockchain.git
cd blockchain
git checkout transaction

# create keys
mkdir -p keys
openssl genpkey -algorithm ed25519 -out keys/keypair0.pem
openssl genpkey -algorithm ed25519 -out keys/keypair1.pem

# build and run
make
./blockchain.py --genesis -p 1234 -k keys/keypair0.pem
```
