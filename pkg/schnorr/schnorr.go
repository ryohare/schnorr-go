package schnorr

import (
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
)

//
// https://pkg.go.dev/github.com/decred/dcrd/dcrec/secp256k1/v4@v4.0.1/schnorr#section-readme
//

var Curve = btcec.S256()

func GetBigIntBytesImmutable(i *big.Int) []byte {
	if len(i.Bytes()) > 32 {
		return nil
	}

	dest := make([]byte, 32)

	copy(dest[32-len(i.Bytes()):], i.Bytes())

	return dest
}

// s*G = R + e*Q
func Sign(privatekey *big.Int, message [32]byte) ([64]byte, error) {
	signature := [64]byte{}

	// check the bounds on the private key passed in
	if privatekey.Cmp(big.NewInt(1)) < 0 || privatekey.Cmp(new(big.Int).Sub(Curve.N, big.NewInt(1))) > 0 {
		return signature, fmt.Errorf("private key must be an integer between 1 and %d", Curve.N)
	}

	// get the d as bytes, known as the private key in schnorr lingo
	d := GetBigIntBytesImmutable(privatekey)

	// get a random nounce value for the signature
	k0, err := getDeterministicK(d, message)
	if err != nil {
		return signature, err
	}

	// Get Rx and Ry from the curve
	rx, ry := Curve.ScalarBaseMult(GetBigIntBytesImmutable(k0))

	// get the true k value now
	k := getK(ry, k0)

	// get Py and Px
	Px, Py := Curve.ScalarBaseMult(d)

	// get the bytes for the Rx value
	rxBytes := GetBigIntBytesImmutable(rx)

	// Get the E value
	e := getE(Px, Py, rxBytes, message)

	// do the actual signing part
	e.Mul(e, privatekey)
	k.Add(k, e)
	k.Mod(k, Curve.N)

	// copy rx to the lower 32 bytes of the result
	copy(signature[:32], rxBytes)

	// copy the k value into the upper 32 bytes of the result
	copy(signature[32:], GetBigIntBytesImmutable(k))

	return signature, nil
}

func Verify(publickey [33]byte, message [32]byte, signature [64]byte) (bool, error) {
	px, py := Unmarshal(Curve, publickey[:])

	// validate the points unmarshalled correctly and land on the curve
	if px == nil || py == nil {
		return false, fmt.Errorf("px or py was unmarshalled to nil")
	}
	if !Curve.IsOnCurve(px, py) {
		return false, fmt.Errorf("px and py are not on the curve")
	}

	// check r against the field size which is the lower 32 bytes of the signature
	r := new(big.Int).SetBytes(signature[:32])
	if r.Cmp(Curve.P) >= 0 {
		return false, fmt.Errorf("r is larger or equal to the field size")
	}

	// check the k against the N value which is the upper 32 bytes of the sig
	s := new(big.Int).SetBytes(signature[32:])
	if s.Cmp(Curve.N) >= 0 {
		return false, fmt.Errorf("s is larger than or equal to curve order N")
	}

	// get the value
	e := getE(px, py, GetBigIntBytesImmutable(r), message)

	// Get the generator points multiplied by the signature
	sgx, sgy := Curve.ScalarBaseMult(GetBigIntBytesImmutable(s))

	// multiply by e the py and px values
	epx, epy := Curve.ScalarMult(px, py, GetBigIntBytesImmutable(e))

	epy.Sub(Curve.P, epy)

	// add up the points we calculated
	rx, ry := Curve.Add(sgx, sgy, epx, epy)

	if rx.Sign() == 0 && ry.Sign() == 0 {
		return false, fmt.Errorf("sign with r[x|y] is 0 indicating the result is 0")
	}
	if big.Jacobi(ry, Curve.P) != 1 {
		return false, fmt.Errorf("failed to validate the jacobi symbol")
	}
	if rx.Cmp(r) != 0 {
		return false, fmt.Errorf("r and rx do not match")
	}

	return true, nil
}

func AggregateSignatures(privatekeys []*big.Int, message [32]byte) ([64]byte, error) {
	signature := [64]byte{}
	if len(privatekeys) == 0 {
		return signature, fmt.Errorf("no private keys supplied")
	}

	k0s := []*big.Int{}
	px, py := new(big.Int), new(big.Int)
	rx, ry := new(big.Int), new(big.Int)

	for _, privatekey := range privatekeys {
		// check the range of the private key
		if privatekey.Cmp(big.NewInt(1)) < 0 || privatekey.Cmp(new(big.Int).Sub(Curve.N, big.NewInt(1))) > 0 {
			return signature, fmt.Errorf("private key is not in the range 1..n-1")
		}

		// this is similar to sign but we add up the signatures together

		// get the bytes of the private key called d
		d := GetBigIntBytesImmutable(privatekey)

		// get a k0 value
		k0i, err := getDeterministicK(d, message)
		if err != nil {
			return signature, err
		}

		rix, riy := Curve.ScalarBaseMult(GetBigIntBytesImmutable(k0i))
		pix, piy := Curve.ScalarBaseMult(d)

		k0s = append(k0s, k0i)

		// add the curves together effectivly stacking the signatures.
		rx, ry = Curve.Add(rx, ry, rix, riy)
		px, py = Curve.Add(px, py, pix, piy)
	}

	// all right, now we have a mega huge signature, time to get the E
	// and create the byte arrays

	newRx := GetBigIntBytesImmutable(rx)
	e := getE(px, py, newRx, message)

	// accumulator for all the k values which get added together
	s := new(big.Int).SetInt64(0)

	// iterate over the signatures and private keys and get a determinstic k for each
	for i, k0 := range k0s {
		k := getK(ry, k0)
		k.Add(k, new(big.Int).Mul(e, privatekeys[i]))
		s.Add(s, k)
	}

	// package into a byte array
	copy(signature[:32], newRx)
	copy(signature[32:], GetBigIntBytesImmutable(s.Mod(s, Curve.N)))

	return signature, nil
}

func getDeterministicK(d []byte, message [32]byte) (*big.Int, error) {
	// niave way to get a random value based on the message however it
	// will ensure that the k value is unique for the message
	h := sha256.Sum256(append(d, message[:]...))
	i := new(big.Int).SetBytes(h[:])

	// ensure the the k value is witin the limits for the N of curve secp256k1
	k0 := i.Mod(i, Curve.N)

	// check that the nonce didnt evaluate to 0
	if k0.Sign() == 0 {
		return nil, fmt.Errorf("k0 is zero")
	}

	return k0, nil
}

func getK(Ry, k *big.Int) *big.Int {
	if big.Jacobi(Ry, Curve.P) == 1 {
		return k
	}
	return k.Sub(Curve.N, k)
}

// Calculate the challenge. e = hash(R || m)
func getE(Px, Py *big.Int, rX []byte, m [32]byte) *big.Int {
	r := append(rX, elliptic.MarshalCompressed(Curve, Px, Py)...)

	// WTF, the unmarshall function doesnt work, need to use
	// the sample one to get it to work
	// data := elliptic.MarshalCompressed(Curve, Px, Py)
	// x, y := elliptic.UnmarshalCompressed(Curve, data)
	// fmt.Println(x, y)

	r = append(r, m[:]...)
	h := sha256.Sum256(r)
	i := new(big.Int).SetBytes(h[:])
	return i.Mod(i, Curve.N)
}

// Marshal converts a point into the form specified in section 2.3.3 of the
// SEC 1 standard.
func Marshal(curve elliptic.Curve, x, y *big.Int) []byte {
	byteLen := (curve.Params().BitSize + 7) >> 3

	ret := make([]byte, 1+byteLen)
	ret[0] = 2 // compressed point

	xBytes := x.Bytes()
	copy(ret[1+byteLen-len(xBytes):], xBytes)
	ret[0] += byte(y.Bit(0))
	return ret
}

// Need to sort out why we need this function here
func Unmarshal(curve elliptic.Curve, data []byte) (x, y *big.Int) {
	byteLen := (curve.Params().BitSize + 7) >> 3
	if (data[0] &^ 1) != 2 {
		return
	}
	if len(data) != 1+byteLen {
		return
	}

	x0 := new(big.Int).SetBytes(data[1 : 1+byteLen])
	P := curve.Params().P
	ySq := new(big.Int)
	ySq.Exp(x0, big.NewInt(3), P)
	ySq.Add(ySq, big.NewInt(7))
	ySq.Mod(ySq, P)
	y0 := new(big.Int)
	P1 := new(big.Int).Add(P, big.NewInt(1))
	d := new(big.Int).Mod(P1, big.NewInt(4))
	P1.Sub(P1, d)
	P1.Div(P1, big.NewInt(4))
	y0.Exp(ySq, P1, P)

	if new(big.Int).Exp(y0, big.NewInt(2), P).Cmp(ySq) != 0 {
		return
	}
	if y0.Bit(0) != uint(data[0]&1) {
		y0.Sub(P, y0)
	}
	x, y = x0, y0
	return
}
