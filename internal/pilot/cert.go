package pilot

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"path/filepath"
	"time"
)

func createCertificates(dir string) error {
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		return e
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	now := time.Now()
	root := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Forensics local pilot CA"}, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true}
	der, e := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if e != nil {
		return e
	}
	ca, e := x509.ParseCertificate(der)
	if e != nil {
		return e
	}
	if e = privateWrite(filepath.Join(dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); e != nil {
		return e
	}
	server, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		return e
	}
	serial, _ = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "lab.forensics"}, DNSNames: []string{"lab.forensics", "localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("10.0.2.100")}, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.AddDate(0, 3, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e = x509.CreateCertificate(rand.Reader, cert, ca, &server.PublicKey, key)
	if e != nil {
		return e
	}
	if e = privateWrite(filepath.Join(dir, "server.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); e != nil {
		return e
	}
	return privateWrite(filepath.Join(dir, "server.key"), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(server)}))
}
