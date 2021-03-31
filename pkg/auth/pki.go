// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package auth

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

const (
	certFilePerm = os.FileMode(0644)
	keyFilePerm  = os.FileMode(0600)
)

// readFileWithPerm reads a file after verifying permissions
func readFileWithPerm(path string, perm os.FileMode) ([]byte, error) {
	const maxFileSizeToRead = 1024 * 1024
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to open %s", path)
	}
	defer func() {
		if err1 := f.Close(); err1 != nil {
			log.Errf("Failed to close %s: %v", path, err1)
		}
	}()

	stat, err := f.Stat()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get file info")
	}
	fPerm := stat.Mode().Perm()
	if fPerm != perm {
		return nil, errors.Errorf(
			"Invalid file permissions. Got: %o Expected: %o", fPerm, perm)
	}
	fInfo, err := os.Stat(filepath.Clean(path))
	if err != nil {
		return nil, errors.Wrap(err, "Failed to stat a file: "+path)
	}
	if fInfo.Size() > maxFileSizeToRead {
		return nil, errors.New("File " + path +
			" seems to be to long:" + fmt.Sprint(fInfo.Size()))
	}
	return ioutil.ReadAll(f)
}

// LoadKey verifies file permissions(0644) and loads a PEM encoded PKCS#8 key
func LoadKey(path string) (crypto.PrivateKey, error) {
	data, err := readFileWithPerm(path, keyFilePerm)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("Failed to decode key")
	}
	if block.Type == "PRIVATE KEY" {
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if block.Type == "EC PRIVATE KEY" {
		return x509.ParseECPrivateKey(block.Bytes)
	}

	return nil, errors.Errorf("%s is not a key (block type: \"%s\")", path, block.Type)
}

// SaveKey saves PEM encoded PKCS#8 key to a file with permissions set to 0644
func SaveKey(key crypto.PrivateKey, path string) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return errors.Wrap(err, "Failed to marshal key")
	}
	data := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		},
	)
	if data == nil {
		return errors.Wrap(err, "Failed to encode key")
	}

	f, err := os.Create(path)
	if err != nil {
		return errors.Wrapf(err, "Failed to open %s", path)
	}
	if err = f.Chmod(keyFilePerm); err != nil {
		if err1 := f.Close(); err1 != nil {
			err = errors.Wrapf(err, "Failed to close file: %#v", err1)
		}
		return errors.Wrap(err, "Failed to set file permissions")
	}
	if _, err = f.Write(data); err != nil {
		if err1 := f.Close(); err1 != nil {
			err = errors.Wrapf(err, "Failed to close file: %#v", err1)
		}
		return errors.Wrap(err, "Failed to write key to file")
	}
	return f.Close()
}

// LoadCert verifies file permissions(0644) and loads a certificate
func LoadCert(path string) (*x509.Certificate, error) {
	certs, err := LoadCerts(path)
	if err != nil {
		return nil, err
	}
	return certs[0], nil
}

// LoadCerts verifies file permissions(0644) and loads all certificates
// If no certificates are found returns an error
func LoadCerts(path string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	data, err := readFileWithPerm(path, certFilePerm)
	if err != nil {
		return nil, err
	}

	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, errors.New("Failed to decode PEM block")
		}
		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to parse certificate")
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, errors.New("Failed to load any certificates")
	}

	return certs, nil
}

// SaveCert saves PEM encoded certificate to a file with permissions set to 0644
func SaveCert(path string, certs ...*x509.Certificate) error {
	f, err := os.Create(path)
	if err != nil {
		return errors.Wrapf(err, "Failed to open %s", path)
	}
	if err = f.Chmod(certFilePerm); err != nil {
		if err1 := f.Close(); err1 != nil {
			err = errors.Wrapf(err, "Failed to close file: %#v", err1)
		}
		return errors.Wrap(err, "Failed to set file permissions")
	}

	for _, cert := range certs {
		if err = pem.Encode(
			f,
			&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			},
		); err != nil {
			if err1 := f.Close(); err1 != nil {
				err = errors.Wrapf(err, "Failed to close file: %#v", err1)
			}
			return errors.Wrapf(err, "Failed to encode certificate to file")
		}
	}
	return f.Close()
}
