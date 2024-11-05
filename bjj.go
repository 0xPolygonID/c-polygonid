package c_polygonid

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/iden3/go-iden3-crypto/babyjub"
)

type BabyJubJubSignPoseidonResponse struct {
	Signature babyjub.SignatureComp `json:"signature"`
}

func BabyJubJubSignPoseidon(ctx context.Context, cfg EnvConfig,
	in []byte) (BabyJubJubSignPoseidonResponse, error) {

	var req struct {
		PrivKey *JsonBJJPrivateKey `json:"private_key"`
		Msg     *JsonFieldIntStr   `json:"msg_int"`
	}

	if in == nil {
		return BabyJubJubSignPoseidonResponse{}, errors.New("request is empty")
	}

	err := json.Unmarshal(in, &req)
	if err != nil {
		return BabyJubJubSignPoseidonResponse{},
			fmt.Errorf("failed to unmarshal request: %w", err)
	}

	if req.PrivKey == nil {
		return BabyJubJubSignPoseidonResponse{},
			errors.New("private key is not set")
	}
	if req.Msg == nil {
		return BabyJubJubSignPoseidonResponse{},
			errors.New("message is not set")
	}

	sig := req.PrivKey.PrivateKey().SignPoseidon(req.Msg.Int())
	return BabyJubJubSignPoseidonResponse{
		Signature: sig.Compress(),
	}, nil
}

type BabyJubJubVerifyPoseidonResponse struct {
	Valid bool `json:"valid"`
}

func BabyJubJubVerifyPoseidon(_ context.Context, _ EnvConfig,
	in []byte) (BabyJubJubVerifyPoseidonResponse, error) {

	var req struct {
		Pub *JsonBJJPublicKey `json:"public_key"`
		Sig *JsonBJJSignature `json:"signature"`
		Msg *JsonFieldIntStr  `json:"msg_int"`
	}

	if in == nil {
		return BabyJubJubVerifyPoseidonResponse{},
			errors.New("request is empty")
	}

	err := json.Unmarshal(in, &req)
	if err != nil {
		return BabyJubJubVerifyPoseidonResponse{},
			fmt.Errorf("failed to unmarshal request: %w", err)
	}

	if req.Pub == nil {
		return BabyJubJubVerifyPoseidonResponse{},
			errors.New("public key is not set")
	}
	if req.Msg == nil {
		return BabyJubJubVerifyPoseidonResponse{},
			errors.New("message is not set")
	}
	if req.Sig == nil {
		return BabyJubJubVerifyPoseidonResponse{},
			errors.New("signature is not set")
	}

	return BabyJubJubVerifyPoseidonResponse{
		Valid: req.Pub.PublicKey().
			VerifyPoseidon(req.Msg.Int(), req.Sig.Signature()),
	}, nil
}

type BabyJubJubPrivate2PublicResponse struct {
	PublicKey  string `json:"public_key"`
	PublicKeyX string `json:"public_key_x_int"`
	PublicKeyY string `json:"public_key_y_int"`
}

func BabyJubJubPrivate2Public(_ context.Context, _ EnvConfig,
	in []byte) (BabyJubJubPrivate2PublicResponse, error) {

	var req struct {
		PrivKey *JsonBJJPrivateKey `json:"private_key"`
	}

	if in == nil {
		return BabyJubJubPrivate2PublicResponse{},
			errors.New("request is empty")
	}

	err := json.Unmarshal(in, &req)
	if err != nil {
		return BabyJubJubPrivate2PublicResponse{},
			fmt.Errorf("failed to unmarshal request: %w", err)
	}

	if req.PrivKey == nil {
		return BabyJubJubPrivate2PublicResponse{},
			errors.New("private key is not set")
	}

	pubKey := req.PrivKey.PrivateKey().Public()
	compPubKey := pubKey.Compress()

	return BabyJubJubPrivate2PublicResponse{
		PublicKey:  hex.EncodeToString(compPubKey[:]),
		PublicKeyX: pubKey.X.Text(10),
		PublicKeyY: pubKey.Y.Text(10),
	}, nil
}

type BabyJubJubPublicUncompressResponse struct {
	PublicKeyX string `json:"public_key_x_int"`
	PublicKeyY string `json:"public_key_y_int"`
}

func BabyJubJubPublicUncompress(_ context.Context, _ EnvConfig,
	in []byte) (BabyJubJubPublicUncompressResponse, error) {

	var req struct {
		Pub *JsonBJJPublicKey `json:"public_key"`
	}

	if in == nil {
		return BabyJubJubPublicUncompressResponse{},
			errors.New("request is empty")
	}

	err := json.Unmarshal(in, &req)
	if err != nil {
		return BabyJubJubPublicUncompressResponse{},
			fmt.Errorf("failed to unmarshal request: %w", err)
	}

	if req.Pub == nil {
		return BabyJubJubPublicUncompressResponse{},
			errors.New("public key is not set")
	}

	return BabyJubJubPublicUncompressResponse{
		PublicKeyX: req.Pub.PublicKey().X.Text(10),
		PublicKeyY: req.Pub.PublicKey().Y.Text(10),
	}, nil
}

type BabyJubJubPublicCompressResponse struct {
	PublicKey string `json:"public_key"`
}

func BabyJubJubPublicCompress(_ context.Context, _ EnvConfig,
	in []byte) (BabyJubJubPublicCompressResponse, error) {

	var req struct {
		PublicKeyX *JsonFieldIntStr `json:"public_key_x_int"`
		PublicKeyY *JsonFieldIntStr `json:"public_key_y_int"`
	}

	if in == nil {
		return BabyJubJubPublicCompressResponse{},
			errors.New("request is empty")
	}

	err := json.Unmarshal(in, &req)
	if err != nil {
		return BabyJubJubPublicCompressResponse{},
			fmt.Errorf("failed to unmarshal request: %w", err)
	}

	if req.PublicKeyX == nil {
		return BabyJubJubPublicCompressResponse{},
			errors.New("public key X is not set")
	}

	if req.PublicKeyY == nil {
		return BabyJubJubPublicCompressResponse{},
			errors.New("public key Y is not set")
	}

	pubKey := babyjub.PublicKey{
		X: req.PublicKeyX.Int(),
		Y: req.PublicKeyY.Int(),
	}
	compPubKey := pubKey.Compress()

	return BabyJubJubPublicCompressResponse{
		PublicKey: hex.EncodeToString(compPubKey[:]),
	}, nil
}
