package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"os"
	"time"
)

func createPrivateKey(path string) (*rsa.PrivateKey, error) {
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	keyPemFile, err := os.Create("./certs/" + path)
	if err != nil {
		return nil, err
	}
	pem.Encode(keyPemFile, &pem.Block{Type: "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey)})
	keyPemFile.Close()
	return caPrivKey, nil
}

//CreateCACerts creates a new private key and a root Certificate. Returns true if creations was successfull
func createCACert() (*x509.Certificate, error) {
	caPrivKey, err := createPrivateKey("rootPrivateKey.key")
	if err != nil {
		return nil, err
	}
	ca := x509.Certificate{
		SerialNumber:          big.NewInt(1337),
		IsCA:                  true,
		Version:               3,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(2, 0, 0),
		Subject:               pkix.Name{CommonName: "my_super_root_id"},
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &ca, &ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, err
	}
	certPemFile, err := os.Create("./certs/rootCert.cert")
	if err != nil {
		return nil, err
	}
	pem.Encode(certPemFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	certPemFile.Close()
	return &ca, nil
}

//Create a Device certificate
func createDeviceCert(deviceId string, rootCert *x509.Certificate, ca_key *rsa.PrivateKey) (*x509.Certificate, error) {
	devicePrivKey, err := createPrivateKey("devicePrivateKey.key")
	if err != nil {
		return nil, err
	}
	device := x509.Certificate{
		SerialNumber: big.NewInt(42),
		IsCA:         false,
		Version:      3,
		Subject:      pkix.Name{CommonName: deviceId},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(2, 0, 0),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &device, rootCert, &devicePrivKey.PublicKey, ca_key)
	if err != nil {
		return nil, err
	}
	//Write device cert
	certPemFile, err := os.Create("./certs/deviceCert.cert")
	if err != nil {
		return nil, err
	}
	pem.Encode(certPemFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	certPemFile.Close()
	return &device, nil
}

//loadKeyloads an existing pem decoded private key and returns an rsa.PrivateKey
func loadKey(fileName string) (*rsa.PrivateKey, error) {
	b, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

//loadCert loads an existing pem decoded certificate and return an x509.Certificate
func loadCert(fileName string) (*x509.Certificate, error) {
	b, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, err
}

//createChainofCertificates takes a slice of certs paths and creates a chain of certificates
func createChainOfCertificates(certs []string, newFilePath string) error {
	var buf bytes.Buffer
	for _, cert := range certs {
		b, err := ioutil.ReadFile(cert)
		if err != nil {
			return err
		}
		buf.Write(b)
	}
	err := ioutil.WriteFile(newFilePath, buf.Bytes(), 0644)
	if err != nil {
		return err
	}
	return nil
}
