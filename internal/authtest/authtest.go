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
MIIClDCCAf2gAwIBAgIJAIXSLKWlmsS7MA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNV
BAYTAlRUMQ8wDQYDVQQIDAZUZXN0Q0ExDzANBgNVBAcMBlRlc3RDQTEPMA0GA1UE
CgwGVGVzdENBMQ8wDQYDVQQLDAZUZXN0Q0ExDzANBgNVBAMMBlRlc3RDQTAgFw0x
OTA2MTcxNTQyNDVaGA8yMTE5MDUyNDE1NDI0NVowYjELMAkGA1UEBhMCVFQxDzAN
BgNVBAgMBlRlc3RDQTEPMA0GA1UEBwwGVGVzdENBMQ8wDQYDVQQKDAZUZXN0Q0Ex
DzANBgNVBAsMBlRlc3RDQTEPMA0GA1UEAwwGVGVzdENBMIGfMA0GCSqGSIb3DQEB
AQUAA4GNADCBiQKBgQDpxwnKZQ9wOiJszFIL8wuhHDWixOLWg+BOypLm3e+lmmbz
5J/mxVN9NCpLWDxauSNOPLyIPfaKR1cdnEA73zzqXHP2qSJ8j5ugMiIDryl0glmt
5f2v4vd6JxHhZgzDUWDIHPH1rXhTTrwpldVJrJpHOrrl+SmvMq3ZJYpZkkyMdwID
AQABo1AwTjAdBgNVHQ4EFgQUkaB3kqHkhYMjPS0sfplRMyFybiAwHwYDVR0jBBgw
FoAUkaB3kqHkhYMjPS0sfplRMyFybiAwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOBgQAXq9+Oy+wrd/yuX8oG3gjUamPkX00Bb3MYPVE6qCwcOHD1U5Gi3deo
wN1oVpmPF62deJ/V26g0D9M20YowmNd+awcDdo0iqTi4SarZXjfizw9X0IIvAAJU
fWBsmtjSpstg01DwfkdaYsXi8y6rD1b/b+rcuqBAPYz+hikp6FDkjA==
-----END CERTIFICATE-----`)
	// ServerKey generated with:
	// openssl genpkey -algorithm RSA
	ServerKey = []byte(`-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJgim/L/pumiQePg
wRUiOY/SsaqryjWCCxaoO4xAlBY7Uah9CQ2A9swUWX8zqfN95r5GY2UrgoeXLYFz
1lBYxT6TMm+b873uOjTYWnQtivvs95vvh6MutbJkZB5+wjH27i0NkZbCpnFwWfIp
BCzpYghQv+0Cg+n5Eq16/ucCS+RDAgMBAAECgYAVbkqpoHnSz5iYkUChyYByUivU
7v49K2SEfI5m43H478JBCdwMmu4pMXSqBo0aT9IBW8kEp2xrzVALvFWkW9ztDBGM
nGpNMVNHXbmr6pOtxS6vVOz43bdYwLxlF2UXh3SCeDncB+/FXhKHnkFqR/YTp7pf
tGo0tN+bGmcXdevFgQJBAMoGWMStJCBSPGNu4/+lCg4c36X9Dru1V11c3CLQ9zqv
rVcKphvsLZnNXjuxNz49X3ReLm2cNVkVV7CqFfUyD2UCQQDAyAWYFRYng+cgJk30
O1erfI0oXkYQ8YjyCG277+2hu8iQ6qYQcD8EeOX8KJLpsPtx9GT+OYhId1ieWMIM
kU6HAkEAu84Cn3NFbjaEpPrlQTYvjscQscH5/E2sFcLJciRIcGn3/j6MBNEd4yij
PWKVNGrhXdBf4M2iWloY1saG+xW6cQJBAIeoufcJb6ui8HP5QIYLdGgin5q2rIuj
zIC1WbMU5Z4YbM09slqDAnV9Nio5yxhUCL1qA9+6UKLeCSh0wSji3+UCQBJjffDz
AMxRO3A9UTRq90xig/ahw2qL5p/jjaEBHLYQT5Htxouf8v8SW1juGoDDtLu5zINk
tVLLjejTegChYGw=
-----END PRIVATE KEY-----`)
	// ServerCert generated with:
	// openssl req -new -key server.key -out server.csr \
	// 	-subj "/C=TT/ST=Server/L=Server/O=Server/OU=Server/CN=localhost"
	// openssl x509 -req -in server.csr -CA cacert.pem -CAkey cakey.pem
	ServerCert = []byte(`-----BEGIN CERTIFICATE-----
MIICPjCCAacCCQCX+oNiYwe8KjANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJU
VDEPMA0GA1UECAwGVGVzdENBMQ8wDQYDVQQHDAZUZXN0Q0ExDzANBgNVBAoMBlRl
c3RDQTEPMA0GA1UECwwGVGVzdENBMQ8wDQYDVQQDDAZUZXN0Q0EwHhcNMTkwNjE3
MTU0MjQ1WhcNMTkwNzE3MTU0MjQ1WjBlMQswCQYDVQQGEwJUVDEPMA0GA1UECAwG
U2VydmVyMQ8wDQYDVQQHDAZTZXJ2ZXIxDzANBgNVBAoMBlNlcnZlcjEPMA0GA1UE
CwwGU2VydmVyMRIwEAYDVQQDDAlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQAD
gY0AMIGJAoGBAJgim/L/pumiQePgwRUiOY/SsaqryjWCCxaoO4xAlBY7Uah9CQ2A
9swUWX8zqfN95r5GY2UrgoeXLYFz1lBYxT6TMm+b873uOjTYWnQtivvs95vvh6Mu
tbJkZB5+wjH27i0NkZbCpnFwWfIpBCzpYghQv+0Cg+n5Eq16/ucCS+RDAgMBAAEw
DQYJKoZIhvcNAQELBQADgYEARjsOHUFmdPEBQv28JwoGUKo+QO83dhNVDU7wY8OU
OxroEz4MyibuXz5mDQ9Z9Yv/IceqxKDxD7f+hu1P8SR+ZwOFO9Cxt9WGK7b9/PJH
vdaw2yfj7wuvG6saYVZa03WWxajkX8F+g1313FikVLq4fztPP/jf5v2yNZf4AKdk
E2k=
-----END CERTIFICATE-----`)
	// ClientKey generated with:
	// openssl genpkey -algorithm RSA
	ClientKey = []byte(`-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAOGhgQQOZcQxZXmm
sVGXGCA10y7ZvpCp4acfjO1UhCVCIz7kMLyhyKkcBAY7p9PihWAiL8GYlfSeVjgG
imbKUYWHz4v+c1MjN+JNfYts5XkgvSzWhsAwgNX+Zr3V+mpZYQyiWK6OzNeksnks
gH//bV50i7x+6zSgc17WReOXecRjAgMBAAECgYEAgZnPDZFniwYEj5fcCk2LohTI
tQSFnXq3DtPkkv4U2YHf1OQlynPzWo+pEBt8DwzyJ4H7hGws1lGMnKnFHb3gjIqW
7ppVhx5TtzcAoJrQ4beOhxAeMQHJ1gc7WBt3Mtq4wAhVFSSytYR2k79zLwQ1AhBo
85YaoSsiNBFySAsR8mECQQDyAJQAs3aMhR6t4HHXpwIqF2nsS7ceASa28GoewFKq
liPzAvXUldmfM2lNO8KmYyPo+rBy96wcW8nY2tqyn9dfAkEA7q6CJIMAHaESfc1p
6jauZgn03hAMXSZFszpgufqkJFYHjVMSrEnNFx9q53axfeYWtdF9Ntx/eQ1i96mW
9j9FfQJAErbQuy0locA5myCcLR0RIcglvMwuIPfd0o/M5QviWKa7qPM1p3bfGVyU
bBCPAObxw/Z+5qUYfijq9wYVm3KY6QJBAIqfgeiQyQ1sUmAMYJpuHcYXvEcIzRWA
t/SLUEhTwOd1q7cx62NzDZGDZsR+FEIJ02DQBchKMiLtWnB657mnL8UCQCtV5/s1
4zoNrRfqjhKvSXOFZMSmg5WiQLGt+5jy4G+LDdEWVCixVQgmadCt5ykgXGlUCgAi
oRbkn/uiMqB1B1E=
-----END PRIVATE KEY-----`)
	// ClientCert generated with:
	// openssl req -new -key clientkey.pem -out client.csr
	//     -subj "/C=TT/ST=Client/L=Client/O=Client/OU=Client/CN=client"
	// openssl x509 -req -in client.csr -CA cacert.pem -CAkey cakey.pem
	ClientCert = []byte(`-----BEGIN CERTIFICATE-----
MIICOzCCAaQCCQCX+oNiYwe8KzANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJU
VDEPMA0GA1UECAwGVGVzdENBMQ8wDQYDVQQHDAZUZXN0Q0ExDzANBgNVBAoMBlRl
c3RDQTEPMA0GA1UECwwGVGVzdENBMQ8wDQYDVQQDDAZUZXN0Q0EwHhcNMTkwNjE3
MTU0MjQ2WhcNMTkwNzE3MTU0MjQ2WjBiMQswCQYDVQQGEwJUVDEPMA0GA1UECAwG
Q2xpZW50MQ8wDQYDVQQHDAZDbGllbnQxDzANBgNVBAoMBkNsaWVudDEPMA0GA1UE
CwwGQ2xpZW50MQ8wDQYDVQQDDAZjbGllbnQwgZ8wDQYJKoZIhvcNAQEBBQADgY0A
MIGJAoGBAOGhgQQOZcQxZXmmsVGXGCA10y7ZvpCp4acfjO1UhCVCIz7kMLyhyKkc
BAY7p9PihWAiL8GYlfSeVjgGimbKUYWHz4v+c1MjN+JNfYts5XkgvSzWhsAwgNX+
Zr3V+mpZYQyiWK6OzNeksnksgH//bV50i7x+6zSgc17WReOXecRjAgMBAAEwDQYJ
KoZIhvcNAQELBQADgYEATfu3lzpQ51xn0Yn4rIKxHqD0rFCm3UUAC1Q8rbjbGv+v
wEomgxm8xhPV4e86rwMXK5zAH0jTVXmctJOeVsRWeIahZzAV5/Lm68QJ+//ACEeR
VsJafwK8vWVb9tkYzsqbVYMnoRDW3EV5j42wy88Z5d6nLtVdXvpA6CJK3nUCMuQ=
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
