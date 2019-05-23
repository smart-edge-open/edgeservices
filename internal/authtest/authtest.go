// Copyright 2019 Intel Corporation and Smart-Edge.com, Inc. All rights reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authtest

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"google.golang.org/grpc/credentials"
)

var (
	// CAKey generated with:
	// openssl genpkey -algorithm RSA
	CAKey = []byte(`-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJmmeSRg9WoH6BC6
dKDAztns763HJfbaGf7Nc1aXPgymmWpHY4W4p79hHPUCbB0jMKayJl4jDHdT23Y1
iPpFLCKuA0qmPbpRF87YyKP+3ImEwc2w9vySGBi5rPPUlqDho6YQLC2ICCxIRwIy
0p+m58GZU2zDtyNTgTBwddMlcwpLAgMBAAECgYBW1lYa8E1jGorWgXqOq8l8MsOW
1DmplMQiVJz98EZaQgHspeIiXiU4LTt/YVoW8Z96Zq72fxp5ikQ7P7BluZhiNQSg
De2r5b95CLvMzSuYY2Kj2I+RcvefTHPLmdIZYbZSbaWQ4GZuPMSOxHXBHePPGXRZ
Vir8SklM8IMzx/Nb+QJBAMf+61K0okQo1tC0BZOJwYIUy9/RjaRZyd8snTFvaJnF
BfH7R41jMpAH2s/dRmlxx7QzAIvOnRoCaNGP9bxfEo0CQQDErTBC3BG+hLfECWI7
oV6fOySrw+c3DfoBe3chrf0HUu0yWi9Rk6vWirODTR2NvW+D8Gbyuj9tReqL5Zfi
ocY3AkEAkociwqW1fVquiJpcu4viSvwRoxpVPGTMksaNJPsLGB5SDMid0+kp0nzu
w/zK6daDCnOTotruH3BEe8WNtUWywQJAYNt1wAeHCY9svLNuWDWBVuOWjKyeqqNM
cvxtz/1Sdg/l1n1JfmA+KRsHiusoWcxoJc73tCP65oKfHqREJ41KAwJAPOR+4/q+
7Rx3nDBI8xFdGsB88vpOUmth8QfhuVs8J6TD0xnl1vX4D2DgN8zMfulnCqrTQ8HZ
HgxaCb6QiaAuBg==
-----END PRIVATE KEY-----`)

	// CACert generated with:
	// openssl req -new -x509 -key cakey.pem -days 36500
	//     -subj "/C=TT/ST=TestCA/L=TestCA/O=TestCA/OU=TestCA/CN=TestCA"
	CACert = []byte(`-----BEGIN CERTIFICATE-----
MIIClDCCAf2gAwIBAgIJAJaf4FK02oiVMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNV
BAYTAlRUMQ8wDQYDVQQIDAZUZXN0Q0ExDzANBgNVBAcMBlRlc3RDQTEPMA0GA1UE
CgwGVGVzdENBMQ8wDQYDVQQLDAZUZXN0Q0ExDzANBgNVBAMMBlRlc3RDQTAgFw0x
OTA1MTUxMzU0MzJaGA8yMTE5MDQyMTEzNTQzMlowYjELMAkGA1UEBhMCVFQxDzAN
BgNVBAgMBlRlc3RDQTEPMA0GA1UEBwwGVGVzdENBMQ8wDQYDVQQKDAZUZXN0Q0Ex
DzANBgNVBAsMBlRlc3RDQTEPMA0GA1UEAwwGVGVzdENBMIGfMA0GCSqGSIb3DQEB
AQUAA4GNADCBiQKBgQCZpnkkYPVqB+gQunSgwM7Z7O+txyX22hn+zXNWlz4Mpplq
R2OFuKe/YRz1AmwdIzCmsiZeIwx3U9t2NYj6RSwirgNKpj26URfO2Mij/tyJhMHN
sPb8khgYuazz1Jag4aOmECwtiAgsSEcCMtKfpufBmVNsw7cjU4EwcHXTJXMKSwID
AQABo1AwTjAdBgNVHQ4EFgQUuKRyB2U43+9n/+fhuxR8RvgDx0owHwYDVR0jBBgw
FoAUuKRyB2U43+9n/+fhuxR8RvgDx0owDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOBgQAcRNMto64zCJeA3PrCHLv93iLO8V5QBR7wvUzbwvzK6Sza4rT9Z7tG
+pJrgs8GJI72pbs4irNrcEiSHDlRB7UHovensphUJ/0NiOKPkv35S+9DbK2PXwc2
tXxnCwBqtkDxAat4qXOH+vT7eMAsmfLLd4Zw10chmnrXF8lo2yUV4w==
-----END CERTIFICATE-----`)
	// ServerKey generated with:
	// openssl genpkey -algorithm RSA
	ServerKey = []byte(`-----BEGIN PRIVATE KEY-----
MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAMOxN67I9Et83s8v
NK8tiRu3FNFYNiJ/oEqGpdqseay2I3+fwyHthfDpQNkjLFO6NoGi2bWyn9PyXsr/
/kz4CkiRhTRRfH6Tvw4veLLLPEaHXsQ1O6tngsYfXt/o/5QevH/a1rPHO36rdLya
5OnS8wIjEWKwgkSQOw/Vb/BHoNWHAgMBAAECgYEAsYsgTNiPI8nH0EswzlpO0bFa
FtCkVMpb4CGnae0fez3ImSqWfDqmUbseFaKevdvtRdI9GWdVMJLtw9lbm/NSR4w0
AZ1HH96h713wL4QkvE2eXWljZTbHmNpR9VNnviDI0gD6SCm5Wnk1k2MLGeE7TJKY
DmNbfmwEYgq/x5+yCXkCQQDnzGkhAO/kp+yeciWzxexCbSCViE7HOmVymkOc9iAs
L5G9YmoZelJpmZS+MZ+SBraUMrVwG9GuNrgSgqysoly7AkEA2B+/UEnVKD9kSO6f
o2XwLAVXR6z+50tAQCd/Btjx62HQ3mYus1UPrMzEvQ6mBg2mjhZ8DQyUzbndwZn7
PtCjpQJAI5+uqHvUYnfMTa2NTculO7A5ycFhGg1Heg1rRrwsxZ2p8EkntTKvZ7tK
uNA3jeGqPaxtZgVgfD28nFuo3f818QJBAMzW0jnjsJ8T7hXd7PoubMMcUMwDYBmS
ThRAGvo/dpMUw6V2jb602UV7UuCpWJwWJg03rF2l1gdiqZaMPgAcOW0CQQCoNNsm
LCjxZy6DpwmcjSdv6Cf4MWXVTDRrnzDp1poGviwAxwmKa16avSAKNIWsTwMDjpD9
eyquZowyeNhRP/tI
-----END PRIVATE KEY-----`)
	// ServerCert generated with:
	// openssl req -new -key server.key -out server.csr \
	// 	-subj "/C=TT/ST=Server/L=Server/O=Server/OU=Server/CN=localhost"
	// openssl x509 -req -in server.csr -CA cacert.pem -CAkey cakey.pem
	ServerCert = []byte(`-----BEGIN CERTIFICATE-----
MIICNjCCAZ8CCQCVytXXmgRitjANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJU
VDEPMA0GA1UECAwGVGVzdENBMQ8wDQYDVQQHDAZUZXN0Q0ExDzANBgNVBAoMBlRl
c3RDQTEPMA0GA1UECwwGVGVzdENBMQ8wDQYDVQQDDAZUZXN0Q0EwHhcNMTkwNTE1
MTM1NjE3WhcNMTkwNjE0MTM1NjE3WjBdMQswCQYDVQQGEwJUVDENMAsGA1UECAwE
VGVzdDENMAsGA1UEBwwEVGVzdDENMAsGA1UECgwEVGVzdDENMAsGA1UECwwEVGVz
dDESMBAGA1UEAwwJbG9jYWxob3N0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
gQDDsTeuyPRLfN7PLzSvLYkbtxTRWDYif6BKhqXarHmstiN/n8Mh7YXw6UDZIyxT
ujaBotm1sp/T8l7K//5M+ApIkYU0UXx+k78OL3iyyzxGh17ENTurZ4LGH17f6P+U
Hrx/2tazxzt+q3S8muTp0vMCIxFisIJEkDsP1W/wR6DVhwIDAQABMA0GCSqGSIb3
DQEBCwUAA4GBAFQRm7ChLJzcPjhj86vRi/5Z2hxTNXrwu1OXuz+hbDGi0MjvCxVY
1ZLiK7MbGEDmOtAC4rsYsNsugQ9qtrpfq0fB7S/VhFzfeGS6BDwRs8J3yyO14mYb
kN4rK2d4xmED7hm+kwOPvHaQqtW4LeMMv0a79z9zvcAPHD+Pob2YY3M/
-----END CERTIFICATE-----`)
	// ClientKey generated with:
	// openssl genpkey -algorithm RSA
	ClientKey = []byte(`-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALZCtEJKAqeCu5AK
mvXPYMZm0GbMIkzUpq0aCDeqk5OeA0ihJOGThRgVwSb0ECgoNFej1f6zcUyhEisD
lsgPSbceV26glAd4VsnIUj1No7jmPlAKOtHv+r/Bxuk/ytVW7BnIw8ZNgm3Q3K3D
naj6XZThAriOGFoLldogaeuFQW3dAgMBAAECgYBg0aJsLGCol3wHknqq5ZTlECzY
zsvRwI0iG1gOKiDnI+Neq6up4PGsz7Ghfbkve9wCSlgdSzl+mXnLO8bXU7e2Fudr
nng1KdL6i2EbQnlj9bdldJsNBRUANk11LYNHZdRyvUq2rRJvIfrIbOlYvWoACA3n
eVpH2P1DyMSmSgyByQJBAOfpwktVKFmK2o8bSYv4/SvpB2PrIHAiZKio1FK8TVcj
Sue1jMriDNhQAYrITJMZj+yN2cLe25ts9D+aUS4cEbcCQQDJMMEKdpGSTV2cC+Lc
j41Vr15bVSrBYM9f50YKEdzsH2WrSrLuOjlvqO+jz9Vy6HHUEqIAb3GtlOI+0Csu
jK0LAkEAlQ1Hg/VadppouDtYfK7twLAHwO9YrNleCoxf0kEWECAtv1iPAcJhcRGS
vCjaFl0ChI3y3G0xheZz4QEElfcSZwJAA4b8S2+qu7LpijvXHWDS7Iank9hZaIyG
9jp6yuBnTCh8wtULcAvLR/7hPLD/IAWdQUeWWYWaq51pngpOR4Gl4wJAYtRkdMGs
DjKLi/u4P3lBL9H4j7Tj44SXceqYgIX7u2CIT8mDjdmYw5cCXMM5o8t1odExqAsp
+ygWuR2KglFc7A==
-----END PRIVATE KEY-----`)
	// ClientCert generated with:
	// openssl req -new -key clientkey.pem -out client.csr
	//     -subj "/C=TT/ST=Client/L=Client/O=Client/OU=Client/CN=client"
	// openssl x509 -req -in client.csr -CA cacert.pem -CAkey cakey.pem
	ClientCert = []byte(`-----BEGIN CERTIFICATE-----
MIICOzCCAaQCCQCVytXXmgRitzANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJU
VDEPMA0GA1UECAwGVGVzdENBMQ8wDQYDVQQHDAZUZXN0Q0ExDzANBgNVBAoMBlRl
c3RDQTEPMA0GA1UECwwGVGVzdENBMQ8wDQYDVQQDDAZUZXN0Q0EwHhcNMTkwNTE1
MTQwMTQyWhcNMTkwNjE0MTQwMTQyWjBiMQswCQYDVQQGEwJUVDEPMA0GA1UECAwG
Q2xpZW50MQ8wDQYDVQQHDAZDbGllbnQxDzANBgNVBAoMBkNsaWVudDEPMA0GA1UE
CwwGQ2xpZW50MQ8wDQYDVQQDDAZjbGllbnQwgZ8wDQYJKoZIhvcNAQEBBQADgY0A
MIGJAoGBALZCtEJKAqeCu5AKmvXPYMZm0GbMIkzUpq0aCDeqk5OeA0ihJOGThRgV
wSb0ECgoNFej1f6zcUyhEisDlsgPSbceV26glAd4VsnIUj1No7jmPlAKOtHv+r/B
xuk/ytVW7BnIw8ZNgm3Q3K3Dnaj6XZThAriOGFoLldogaeuFQW3dAgMBAAEwDQYJ
KoZIhvcNAQELBQADgYEAfj1vtlSHv9PKLAyKeTcCuBg0Qhe4anirrTmTtFN/uQ2p
M/0e2GyszDyB3Deu1fJ20c4c4xzBXBe9yAJC0YA235u8Byz8gd6WjJ/qTN3BtxJg
Ks7sHDXS3rYZyU5zdRcEr0BYjUfp4ugZtskEJjEIMWtqSlG4uVEkTpRmOP7q0NA=
-----END CERTIFICATE-----`)
)

// EnrollStub performs fake enrollment by saving hardcoded keys and certificates
// This should be used only for testing
func EnrollStub(certsDir string) error {
	if err := os.MkdirAll(certsDir, 0700); err != nil {
		return errors.Wrapf(err, "Failed to create %s", certsDir)
	}

	if err := ioutil.WriteFile(filepath.Join(certsDir, "key.pem"),
		ServerKey, 0600); err != nil {
		return errors.Wrap(err, "Failed to save key")
	}

	if err := ioutil.WriteFile(filepath.Join(certsDir, "cert.pem"),
		ServerCert, 0600); err != nil {
		return errors.Wrap(err, "Failed to save cert")
	}

	if err := ioutil.WriteFile(filepath.Join(certsDir, "cacerts.pem"),
		CACert, 0600); err != nil {
		return errors.Wrap(err, "Failed to save cacerts")
	}

	if err := ioutil.WriteFile(filepath.Join(certsDir, "root.pem"),
		CACert, 0600); err != nil {
		return errors.Wrap(err, "Failed to save root ca")
	}
	return nil
}

// ClientCredentialsStub return TLS credentials based on hardcoded keys and
// certificates. This should be used only for testing
func ClientCredentialsStub() (credentials.TransportCredentials, error) {
	cert, err := tls.X509KeyPair(ClientCert, ClientKey)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to load key pair")
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(CACert) {
		return nil, errors.New("Failed to add certs to pool")
	}
	return credentials.NewTLS(&tls.Config{
		ServerName:   "localhost",
		Certificates: []tls.Certificate{cert},
		RootCAs:      certPool,
	}), nil
}
