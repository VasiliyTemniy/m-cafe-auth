package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
)

var (
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	tries      = 0
)

/**
 * Create certificates
 * @param target string - certificate target
 */
func CreateCertificates(target string) {

	filePath := "cert/" + target + "/"

	// Create the necessary directories
	dir := filepath.Dir(filePath)
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		panic(err)
	}

	// Generate the private and public keys
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	publicKey := &privateKey.PublicKey

	// Encode the private key
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Get private key file path
	privateKeyFilePath := filepath.Join(dir, "private.pem")

	// Open and truncate the file
	privateKeyFile, err := os.OpenFile(privateKeyFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		panic(err)
	}
	defer privateKeyFile.Close()

	// Write the private key
	err = os.WriteFile(privateKeyFilePath, privateKeyPEM, 0644)
	if err != nil {
		panic(err)
	}

	// Encode the public key
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		panic(err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// Get public key file path
	publicKeyFilePath := filepath.Join(dir, "public.pem")

	// Open and truncate the file
	publicKeyFile, err := os.OpenFile(publicKeyFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		panic(err)
	}
	defer publicKeyFile.Close()

	// Write the public key
	err = os.WriteFile(publicKeyFilePath, publicKeyPEM, 0644)
	if err != nil {
		panic(err)
	}
}

func ReadCertificates(target string) {

	if tries > 5 {
		panic("Too many tries: could not read or create certificates")
	}

	tries++

	filePath := "cert/" + target + "/"

	// Get private key file path
	privateKeyFilePath := filepath.Join(filePath, "private.pem")

	// Read private key .pem file
	privateKeyPEM, err := os.ReadFile(privateKeyFilePath)
	if err != nil {
		// Create certificates if they do not exist, then try to read them again
		CreateCertificates(target)
		ReadCertificates(target)
		return
	}

	// Decode the pem file
	privateKeyBlock, _ := pem.Decode(privateKeyPEM)

	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		// Create certificates if private key is invalid or corrupt, then try to read them again
		CreateCertificates(target)
		ReadCertificates(target)
		return
	}

	PublicKey = &privateKey.PublicKey
	PrivateKey = privateKey
}
