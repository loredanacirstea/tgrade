# Tgrade


## Development

### Local testnet
* Install
```sh
make install
```
* Setup network
```sh
tgrade testnet --chain-id=testing --output-dir=$(pwd)/testnet --v=1 --keyring-backend=test --commit-timeout=1000ms --minimum-gas-prices="" --single-host true --chain-id=tgrade_7000-1 --trace
```
* Start a validator node
```sh
tgrade start --home=./testnet/node0/tgrade
```

## License

Apache 2.0, see [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
