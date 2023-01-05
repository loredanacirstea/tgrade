package tests

import (
	"fmt"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/simulation"
)

func GenerateRandomAccount() simulation.Account {
	pk := ed25519.GenPrivKey()
	privKey := secp256k1.GenPrivKeyFromSecret(pk.GetKey().Seed())
	pubKey := privKey.PubKey()
	address := sdk.AccAddress(pubKey.Address())
	account := simulation.Account{
		PrivKey: privKey,
		PubKey:  pubKey,
		Address: address,
	}
	return account
}

var _ keyring.Signer = &Signer{}

// Signer defines a type that is used on testing for signing MsgEthereumTx
type Signer struct {
	privKey cryptotypes.PrivKey
}

func NewSigner(sk cryptotypes.PrivKey) keyring.Signer {
	return &Signer{
		privKey: sk,
	}
}

// Sign signs the message using the underlying private key
func (s Signer) Sign(_ string, msg []byte) ([]byte, cryptotypes.PubKey, error) {
	if s.privKey.Type() != "secp256k1" {
		return nil, nil, fmt.Errorf(
			"invalid private key type for signing ewasm tx; expected %s, got %s",
			"secp256k1",
			s.privKey.Type(),
		)
	}

	sig, err := s.privKey.Sign(msg)
	if err != nil {
		return nil, nil, err
	}
	sig = append(sig, byte(28))

	return sig, s.privKey.PubKey(), nil
}

// SignByAddress sign byte messages with a user key providing the address.
func (s Signer) SignByAddress(address sdk.Address, msg []byte) ([]byte, cryptotypes.PubKey, error) {
	signer := sdk.AccAddress(s.privKey.PubKey().Address())
	if !signer.Equals(address) {
		return nil, nil, fmt.Errorf("address mismatch: signer %s ≠ given address %s", signer, address)
	}

	return s.Sign("", msg)
}
