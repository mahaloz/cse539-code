package utils

/****
 * WARNING!!! These are bogus keys for evaluation purposes only.
 * NEVER NEVER NEVER use these keys in a real deployment.
 */

import (
	"crypto/tls"
	"encoding/hex"
	"log"

	"golang.org/x/crypto/nacl/box"
)

var serverPublicKeys = [...]string{
	`-----BEGIN CERTIFICATE-----
MIIBVTCB/KADAgECAgEAMAoGCCqGSM49BAMCMBIxEDAOBgNVBAoTB0FjbWUgQ28w
HhcNMTQwNTAyMDQ0NDM4WhcNMTUwNTAyMDQ0NDM4WjASMRAwDgYDVQQKEwdBY21l
IENvMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEU7EtIv3GVZKMduiOwmQBzrqI
XnF84tNhcPSNtnw8cTgF8CPfJ0wcCbIvgQXEeZpTgn+A5N7YpdooUiwtICadeKND
MEEwDgYDVR0PAQH/BAQDAgCgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB
/wQCMAAwDAYDVR0RBAUwA4IBKjAKBggqhkjOPQQDAgNIADBFAiBU0cZRnenXWw0Y
OgQekAT+sx64ptjzm+ruABzBcIggbQIhAL2XbTx1l8IgmxtQZnK5S9wUmiIYMSxz
F2OaCRUekyth
-----END CERTIFICATE-----
`,
	`
-----BEGIN CERTIFICATE-----
MIIBVjCB/KADAgECAgEAMAoGCCqGSM49BAMCMBIxEDAOBgNVBAoTB0FjbWUgQ28w
HhcNMTQwNTAyMDQ0NDM4WhcNMTUwNTAyMDQ0NDM4WjASMRAwDgYDVQQKEwdBY21l
IENvMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPjQJxCyQ6TeBj/1wd6lPRjQY
NXZs5dfSWv5C0Ww3TWgRBjdrDVO/Lb6T3EQNE4yFEliVJGtAOqUyzvr1aG3xxaND
MEEwDgYDVR0PAQH/BAQDAgCgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB
/wQCMAAwDAYDVR0RBAUwA4IBKjAKBggqhkjOPQQDAgNJADBGAiEAqlPLIKWz8V+z
PIe1umQxfBnxTV4oy6XC47nvXLjZc58CIQDuVbvUmpwGYYHCTpZ8JaONO99OHdls
4AGK2zbn1h2Wnw==
-----END CERTIFICATE-----
`,
	`
-----BEGIN CERTIFICATE-----
MIIBVDCB/KADAgECAgEAMAoGCCqGSM49BAMCMBIxEDAOBgNVBAoTB0FjbWUgQ28w
HhcNMTQwNTAyMDQ0NDM4WhcNMTUwNTAyMDQ0NDM4WjASMRAwDgYDVQQKEwdBY21l
IENvMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWMkR1Mk/2Fcr54HATbXb6JWq
LSiCO/4SoKBkablEj0CJFcASn0CFnNrBaEtKemdJU3JWjhtTE3xRdJ7xWOUayKND
MEEwDgYDVR0PAQH/BAQDAgCgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB
/wQCMAAwDAYDVR0RBAUwA4IBKjAKBggqhkjOPQQDAgNHADBEAiB6hu0ofX3lrJfW
O7GNlJ3NIFqjXvK4nRBaAxWJYcoVPAIgBvHYVaJr1Sywsx5AijvEtAHRGf4PMunK
poajaz5QGmI=
-----END CERTIFICATE-----
`,
	`
-----BEGIN CERTIFICATE-----
MIIBVTCB/KADAgECAgEAMAoGCCqGSM49BAMCMBIxEDAOBgNVBAoTB0FjbWUgQ28w
HhcNMTQwNTAyMDQ0NDM4WhcNMTUwNTAyMDQ0NDM4WjASMRAwDgYDVQQKEwdBY21l
IENvMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3wyLljq332aGf2TWqvu9CXFZ
62mbJkwtzXES1YMq4GX9OhDeO+BlfWDr1wz/HhD4eNuOf+S+8IKljhJfp5Cjz6ND
MEEwDgYDVR0PAQH/BAQDAgCgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB
/wQCMAAwDAYDVR0RBAUwA4IBKjAKBggqhkjOPQQDAgNIADBFAiAVI/oGuIjeKGUI
vF1qt6KnFRMszaMkk7rB6Zh7gQLk0gIhAPofW+nvXYJIfWmqzym7nsC7boWYSndQ
IohyUIqbVRbT
-----END CERTIFICATE-----
`,
	`
-----BEGIN CERTIFICATE-----
MIIBVTCB/KADAgECAgEAMAoGCCqGSM49BAMCMBIxEDAOBgNVBAoTB0FjbWUgQ28w
HhcNMTQwNTAyMDQ0NDM4WhcNMTUwNTAyMDQ0NDM4WjASMRAwDgYDVQQKEwdBY21l
IENvMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0/xg65LUUXolVPEiWsfeaXYf
h3ekEC/oQz2yRVXdiwYcLsdUdy6HfPA/ukH8ZPhNANIgCMd4vw9rdMXUHLdACqND
MEEwDgYDVR0PAQH/BAQDAgCgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB
/wQCMAAwDAYDVR0RBAUwA4IBKjAKBggqhkjOPQQDAgNIADBFAiBoAcoMYznnz7TK
sb00VvupLeDh3u3mNbyCeE8iF8ClkQIhAMyosQNPwStk7QDXK1PlkmmyCfivUzKo
V1YZJb4mXzGy
-----END CERTIFICATE-----
`,
	`
-----BEGIN CERTIFICATE-----
MIIBVjCB/KADAgECAgEAMAoGCCqGSM49BAMCMBIxEDAOBgNVBAoTB0FjbWUgQ28w
HhcNMTQwNTAyMDQ0NDM4WhcNMTUwNTAyMDQ0NDM4WjASMRAwDgYDVQQKEwdBY21l
IENvMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENkXFTC8hiHl01qbatIq5bOYi
roKcqdQj9OeY86v8d6maIKJSn3tmVqBPkMBMiXp5KIj+5l7ng91m7lDvxfXiCKND
MEEwDgYDVR0PAQH/BAQDAgCgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB
/wQCMAAwDAYDVR0RBAUwA4IBKjAKBggqhkjOPQQDAgNJADBGAiEAp2sJBsmFaMSz
HAtdCZoNYaxhWSZD1P6gx3e/a5P0tEsCIQC6dUWN/plC0PFU97JrYiC7AwzF8Ya6
QdavTnOAhS/N7Q==
-----END CERTIFICATE-----
`,
	`
-----BEGIN CERTIFICATE-----
MIIBVDCB/KADAgECAgEAMAoGCCqGSM49BAMCMBIxEDAOBgNVBAoTB0FjbWUgQ28w
HhcNMTQwNTAyMDQ0NDM4WhcNMTUwNTAyMDQ0NDM4WjASMRAwDgYDVQQKEwdBY21l
IENvMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPQrr1gWk51HM1ca2BLxSlfpl
wyN1I7zjGff5YBOdUFn+FaLOO5mdvl5TZm2bm8GEq/TbN9eO0b+N2gTGhO9Vo6ND
MEEwDgYDVR0PAQH/BAQDAgCgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB
/wQCMAAwDAYDVR0RBAUwA4IBKjAKBggqhkjOPQQDAgNHADBEAiAglqJlptAJuipu
IoU4P7a6JP8+Sa7ZNIE3FM5lQTZcTwIgKsYq/jDlRrHnIHRXUJ/86QX9fjOBe40i
l4wvxcK5jDc=
-----END CERTIFICATE-----
`,
	`
-----BEGIN CERTIFICATE-----
MIIBVTCB/KADAgECAgEAMAoGCCqGSM49BAMCMBIxEDAOBgNVBAoTB0FjbWUgQ28w
HhcNMTQwNTAyMDQ0NDM4WhcNMTUwNTAyMDQ0NDM4WjASMRAwDgYDVQQKEwdBY21l
IENvMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3g2SIWXR3k3I5hZfqDMiUT0Y
SQDykiDTgg5uETdPdAhZPJ39/E5+V/K8xwgloqgWrYp4UlXRxsERVVAQYpDbp6ND
MEEwDgYDVR0PAQH/BAQDAgCgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB
/wQCMAAwDAYDVR0RBAUwA4IBKjAKBggqhkjOPQQDAgNIADBFAiEAmf6mTniyhmOd
wTs7kjJVSrOthmC9tJXTr0oTR/1wRugCIAZeLrRcNHMEzRpkmiQdSRTeONOBIW2A
feAWwxR7t/aH
-----END CERTIFICATE-----
`,
	`
-----BEGIN CERTIFICATE-----
MIIBVDCB/KADAgECAgEAMAoGCCqGSM49BAMCMBIxEDAOBgNVBAoTB0FjbWUgQ28w
HhcNMTQwNTAyMDQ0NDM4WhcNMTUwNTAyMDQ0NDM4WjASMRAwDgYDVQQKEwdBY21l
IENvMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZdTOsGmwQEQh9ng9V+xCs4nO
Ce9sueq+kXy6IwRn9dg+KHJ50TyyRkp0cVZ5Msra5hPxl31wHn1Bt6bkdJFkCqND
MEEwDgYDVR0PAQH/BAQDAgCgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB
/wQCMAAwDAYDVR0RBAUwA4IBKjAKBggqhkjOPQQDAgNHADBEAiBybiwCHL/q1BQ7
mMmDknxmZx/lyalZT2FMy1oVhW9RYQIgMgLPrwBUgJ50sAxlEmrF5uHdTROwX3S6
71JcdYbM/dU=
-----END CERTIFICATE-----
`,
	`
-----BEGIN CERTIFICATE-----
MIIBVTCB/KADAgECAgEAMAoGCCqGSM49BAMCMBIxEDAOBgNVBAoTB0FjbWUgQ28w
HhcNMTQwNTAyMDQ0NDM4WhcNMTUwNTAyMDQ0NDM4WjASMRAwDgYDVQQKEwdBY21l
IENvMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEn4k6kY5EHBGKvhs6FYK8jAX3
IntVbjqEkSvut8mKGvaXwvSCUH2TwTrFkq+puJPZoypyB6Y+41IAyAz+Xd8rh6ND
MEEwDgYDVR0PAQH/BAQDAgCgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB
/wQCMAAwDAYDVR0RBAUwA4IBKjAKBggqhkjOPQQDAgNIADBFAiEA3rYIWKpk+Y0G
wRXTW+qLbKJ3RJhHIvj/wH9ZtSH2348CIBVfIHbgwbUrzbAvt0KE08/M9xJqU92F
pDQcupxirXoo
-----END CERTIFICATE-----
`,
	`
-----BEGIN CERTIFICATE-----
MIIBVTCB/KADAgECAgEAMAoGCCqGSM49BAMCMBIxEDAOBgNVBAoTB0FjbWUgQ28w
HhcNMTQwNTAyMDQ0NDM4WhcNMTUwNTAyMDQ0NDM4WjASMRAwDgYDVQQKEwdBY21l
IENvMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEU7EtIv3GVZKMduiOwmQBzrqI
XnF84tNhcPSNtnw8cTgF8CPfJ0wcCbIvgQXEeZpTgn+A5N7YpdooUiwtICadeKND
MEEwDgYDVR0PAQH/BAQDAgCgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB
/wQCMAAwDAYDVR0RBAUwA4IBKjAKBggqhkjOPQQDAgNIADBFAiBU0cZRnenXWw0Y
OgQekAT+sx64ptjzm+ruABzBcIggbQIhAL2XbTx1l8IgmxtQZnK5S9wUmiIYMSxz
F2OaCRUekyth
-----END CERTIFICATE-----
`,
	`
-----BEGIN CERTIFICATE-----
MIIBVjCB/KADAgECAgEAMAoGCCqGSM49BAMCMBIxEDAOBgNVBAoTB0FjbWUgQ28w
HhcNMTQwNTAyMDQ0NDM4WhcNMTUwNTAyMDQ0NDM4WjASMRAwDgYDVQQKEwdBY21l
IENvMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPjQJxCyQ6TeBj/1wd6lPRjQY
NXZs5dfSWv5C0Ww3TWgRBjdrDVO/Lb6T3EQNE4yFEliVJGtAOqUyzvr1aG3xxaND
MEEwDgYDVR0PAQH/BAQDAgCgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB
/wQCMAAwDAYDVR0RBAUwA4IBKjAKBggqhkjOPQQDAgNJADBGAiEAqlPLIKWz8V+z
PIe1umQxfBnxTV4oy6XC47nvXLjZc58CIQDuVbvUmpwGYYHCTpZ8JaONO99OHdls
4AGK2zbn1h2Wnw==
-----END CERTIFICATE-----
`,
	`
-----BEGIN CERTIFICATE-----
MIIBVDCB/KADAgECAgEAMAoGCCqGSM49BAMCMBIxEDAOBgNVBAoTB0FjbWUgQ28w
HhcNMTQwNTAyMDQ0NDM4WhcNMTUwNTAyMDQ0NDM4WjASMRAwDgYDVQQKEwdBY21l
IENvMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWMkR1Mk/2Fcr54HATbXb6JWq
LSiCO/4SoKBkablEj0CJFcASn0CFnNrBaEtKemdJU3JWjhtTE3xRdJ7xWOUayKND
MEEwDgYDVR0PAQH/BAQDAgCgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB
/wQCMAAwDAYDVR0RBAUwA4IBKjAKBggqhkjOPQQDAgNHADBEAiB6hu0ofX3lrJfW
O7GNlJ3NIFqjXvK4nRBaAxWJYcoVPAIgBvHYVaJr1Sywsx5AijvEtAHRGf4PMunK
poajaz5QGmI=
-----END CERTIFICATE-----
`,
	`
-----BEGIN CERTIFICATE-----
MIIBVTCB/KADAgECAgEAMAoGCCqGSM49BAMCMBIxEDAOBgNVBAoTB0FjbWUgQ28w
HhcNMTQwNTAyMDQ0NDM4WhcNMTUwNTAyMDQ0NDM4WjASMRAwDgYDVQQKEwdBY21l
IENvMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3wyLljq332aGf2TWqvu9CXFZ
62mbJkwtzXES1YMq4GX9OhDeO+BlfWDr1wz/HhD4eNuOf+S+8IKljhJfp5Cjz6ND
MEEwDgYDVR0PAQH/BAQDAgCgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB
/wQCMAAwDAYDVR0RBAUwA4IBKjAKBggqhkjOPQQDAgNIADBFAiAVI/oGuIjeKGUI
vF1qt6KnFRMszaMkk7rB6Zh7gQLk0gIhAPofW+nvXYJIfWmqzym7nsC7boWYSndQ
IohyUIqbVRbT
-----END CERTIFICATE-----
`,
	`
-----BEGIN CERTIFICATE-----
MIIBVTCB/KADAgECAgEAMAoGCCqGSM49BAMCMBIxEDAOBgNVBAoTB0FjbWUgQ28w
HhcNMTQwNTAyMDQ0NDM4WhcNMTUwNTAyMDQ0NDM4WjASMRAwDgYDVQQKEwdBY21l
IENvMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0/xg65LUUXolVPEiWsfeaXYf
h3ekEC/oQz2yRVXdiwYcLsdUdy6HfPA/ukH8ZPhNANIgCMd4vw9rdMXUHLdACqND
MEEwDgYDVR0PAQH/BAQDAgCgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB
/wQCMAAwDAYDVR0RBAUwA4IBKjAKBggqhkjOPQQDAgNIADBFAiBoAcoMYznnz7TK
sb00VvupLeDh3u3mNbyCeE8iF8ClkQIhAMyosQNPwStk7QDXK1PlkmmyCfivUzKo
V1YZJb4mXzGy
-----END CERTIFICATE-----
`,
}

var serverSecretKeys = [...]string{
	`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKbLcggTNozKjPjKdF2ZL/cT1i0UnT2gkcSi+sqxBebioAoGCCqGSM49
AwEHoUQDQgAEU7EtIv3GVZKMduiOwmQBzrqIXnF84tNhcPSNtnw8cTgF8CPfJ0wc
CbIvgQXEeZpTgn+A5N7YpdooUiwtICadeA==
-----END EC PRIVATE KEY-----
`,
	`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJKmTtsm/LGGpTO/2f7gQ1KMWlk7MLhFYjOWu/3huxkOoAoGCCqGSM49
AwEHoUQDQgAEPjQJxCyQ6TeBj/1wd6lPRjQYNXZs5dfSWv5C0Ww3TWgRBjdrDVO/
Lb6T3EQNE4yFEliVJGtAOqUyzvr1aG3xxQ==
-----END EC PRIVATE KEY-----
`,
	`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIOoeOek7Z42E+QhGQQttgzBT56+KDxEu0/f0yVqUNIBIoAoGCCqGSM49
AwEHoUQDQgAEWMkR1Mk/2Fcr54HATbXb6JWqLSiCO/4SoKBkablEj0CJFcASn0CF
nNrBaEtKemdJU3JWjhtTE3xRdJ7xWOUayA==
-----END EC PRIVATE KEY-----
`,
	`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMCjStdTf5KBGTewk8vUYphh1WyXfPd9TkqsGbKdk0ySoAoGCCqGSM49
AwEHoUQDQgAE3wyLljq332aGf2TWqvu9CXFZ62mbJkwtzXES1YMq4GX9OhDeO+Bl
fWDr1wz/HhD4eNuOf+S+8IKljhJfp5Cjzw==
-----END EC PRIVATE KEY-----
`,
	`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMJL9A5Ciq0w9uhuf14dDp6zNCiMW3fEDcHhuan6TUkloAoGCCqGSM49
AwEHoUQDQgAE0/xg65LUUXolVPEiWsfeaXYfh3ekEC/oQz2yRVXdiwYcLsdUdy6H
fPA/ukH8ZPhNANIgCMd4vw9rdMXUHLdACg==
-----END EC PRIVATE KEY-----
`,
	`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIE61mLLIOejr0c1Lbv9gVru0x3ivqR7mxRIxUE1BWUJ5oAoGCCqGSM49
AwEHoUQDQgAENkXFTC8hiHl01qbatIq5bOYiroKcqdQj9OeY86v8d6maIKJSn3tm
VqBPkMBMiXp5KIj+5l7ng91m7lDvxfXiCA==
-----END EC PRIVATE KEY-----
`,
	`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEC9piD0FSF605EWj4YtDuRlZEVuKdGvilQqG7f5mRbNoAoGCCqGSM49
AwEHoUQDQgAEPQrr1gWk51HM1ca2BLxSlfplwyN1I7zjGff5YBOdUFn+FaLOO5md
vl5TZm2bm8GEq/TbN9eO0b+N2gTGhO9Vow==
-----END EC PRIVATE KEY-----
`,
	`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJnNbd+RRhsRKFnHcu86MXm6pg6N86d5yxKcEMpt7SRfoAoGCCqGSM49
AwEHoUQDQgAE3g2SIWXR3k3I5hZfqDMiUT0YSQDykiDTgg5uETdPdAhZPJ39/E5+
V/K8xwgloqgWrYp4UlXRxsERVVAQYpDbpw==
-----END EC PRIVATE KEY-----
`,
	`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEZwS5X2mI/UY4n1jYON0M0isI/EW7+OzWQR8Huq6x67oAoGCCqGSM49
AwEHoUQDQgAEZdTOsGmwQEQh9ng9V+xCs4nOCe9sueq+kXy6IwRn9dg+KHJ50Tyy
Rkp0cVZ5Msra5hPxl31wHn1Bt6bkdJFkCg==
-----END EC PRIVATE KEY-----
`,
	`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIN5j5ZgHyklT248GybSdtyzHT/v2uJs9rsk0tg1G3cc/oAoGCCqGSM49
AwEHoUQDQgAEn4k6kY5EHBGKvhs6FYK8jAX3IntVbjqEkSvut8mKGvaXwvSCUH2T
wTrFkq+puJPZoypyB6Y+41IAyAz+Xd8rhw==
-----END EC PRIVATE KEY-----
`,
	`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKbLcggTNozKjPjKdF2ZL/cT1i0UnT2gkcSi+sqxBebioAoGCCqGSM49
AwEHoUQDQgAEU7EtIv3GVZKMduiOwmQBzrqIXnF84tNhcPSNtnw8cTgF8CPfJ0wc
CbIvgQXEeZpTgn+A5N7YpdooUiwtICadeA==
-----END EC PRIVATE KEY-----
`,
	`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJKmTtsm/LGGpTO/2f7gQ1KMWlk7MLhFYjOWu/3huxkOoAoGCCqGSM49
AwEHoUQDQgAEPjQJxCyQ6TeBj/1wd6lPRjQYNXZs5dfSWv5C0Ww3TWgRBjdrDVO/
Lb6T3EQNE4yFEliVJGtAOqUyzvr1aG3xxQ==
-----END EC PRIVATE KEY-----
`,
	`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIOoeOek7Z42E+QhGQQttgzBT56+KDxEu0/f0yVqUNIBIoAoGCCqGSM49
AwEHoUQDQgAEWMkR1Mk/2Fcr54HATbXb6JWqLSiCO/4SoKBkablEj0CJFcASn0CF
nNrBaEtKemdJU3JWjhtTE3xRdJ7xWOUayA==
-----END EC PRIVATE KEY-----
`,
	`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMCjStdTf5KBGTewk8vUYphh1WyXfPd9TkqsGbKdk0ySoAoGCCqGSM49
AwEHoUQDQgAE3wyLljq332aGf2TWqvu9CXFZ62mbJkwtzXES1YMq4GX9OhDeO+Bl
fWDr1wz/HhD4eNuOf+S+8IKljhJfp5Cjzw==
-----END EC PRIVATE KEY-----
`,
	`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMJL9A5Ciq0w9uhuf14dDp6zNCiMW3fEDcHhuan6TUkloAoGCCqGSM49
AwEHoUQDQgAE0/xg65LUUXolVPEiWsfeaXYfh3ekEC/oQz2yRVXdiwYcLsdUdy6H
fPA/ukH8ZPhNANIgCMd4vw9rdMXUHLdACg==
-----END EC PRIVATE KEY--
`,
}

var serverBoxPublicHex = [...]string{
	"25e7a9139b43eb5d6ef39a5069d597d6b9d353bd5fbae3f3df3d316d5c61bc5c",
	"077e8ae1bfb51ab8b8e76df4ee29ec0902b3777bef1c5d6b82697f53c54d2504",
	"7f14438b4092f8d478beffcc610a295331350752efcb4790366d864ba7fbd511",
	"354743620132eb5de8686e62570850015bd2f26532802e2cfd63afd7ef480377",
	"6632f896d0751a3f4bf96da84d8bb3a24d41de6074c1a1b83022526f68fba755",
	"acf3aeb872d324acdf819c4b44495044f01ba14d4a3718cc881a77779d105d19",
	"28494083f96f10ab2311d03befa6e55f7ba98ccecf08cb976d573dcdca4c6166",
	"b31a6715e5f7a01b70e3bb303ebb00a65564fb331274349e821fd788db9a555b",
	"fcf7183219816a2a28d8c4a169b12ab336717e0f3a998415670a2eec80dfe31c",
}

var serverBoxPrivateHex = [...]string{
	"464b531592c58a12652b0dd9a3325c59c0e48a2f3dd31aaec81b1e892f07e9a9",
	"f8c86766dac706e8900c0eca59ef6212dee9a4c32ef4b115d9f11f225bc48379",
	"f62d683d3681985913a50f62412ee90115351b8e0636356e44005e9f2d9870ab",
	"52fc8e19e54bd654fbc30f080cb29dabba2ca6a187ecb216609d007d26030e53",
	"f4cd1678e76c21bcbfa4c74cbfc81400f8fba240692c80e5afe9594a859187db",
	"a32a99f819355dcbfee58439c4fffacad22e6835f2066bbf8a5878e7cf92b375",
	"f9272567e991c5a2edd08d201e8d9991f3a6519b46b1680e13c06b9907b3e27f",
	"42708fe3599f675feb648bd4205527efc1626d6f630d83422e56f439fe24749a",
	"00f17096c80fd24abc4a05d2b6e40b2a525ef66b8e982777c37b470c43efe146",
}

var ServerCertificates []tls.Certificate
var LeaderCertificate tls.Certificate
var ServerBoxPublicKeys []*[32]byte
var ServerBoxPrivateKeys []*[32]byte
var SharedSecrets [][][32]byte

func stringToArray(s string) *[32]byte {
	arr := new([32]byte)
	key, err := hex.DecodeString(s)
	if err != nil {
		log.Fatal("Could not create key:", err)
	}

	if len(key) != 32 {
		log.Fatal("Incorrect key len")
	}

	copy((*arr)[:], key)
	return arr
}

func init() {
	nServers := 8

	var err error
	ServerCertificates = make([]tls.Certificate, nServers)
	ServerBoxPublicKeys = make([]*[32]byte, nServers)
	ServerBoxPrivateKeys = make([]*[32]byte, nServers)

	for i := 0; i < nServers; i++ {
		ServerCertificates[i], err = tls.X509KeyPair(
			[]byte(serverPublicKeys[i]),
			[]byte(serverSecretKeys[i]))
		if err != nil {
			log.Fatal("Could not load certficate #%v %v", i, err)
		}

		ServerBoxPublicKeys[i] = stringToArray(serverBoxPublicHex[i])
		ServerBoxPrivateKeys[i] = stringToArray(serverBoxPrivateHex[i])

	}

	SharedSecrets = make([][][32]byte, nServers)
	for i := 0; i < nServers; i++ {
		SharedSecrets[i] = make([][32]byte, nServers)
		for j := 0; j < nServers; j++ {
			box.Precompute(&SharedSecrets[i][j], ServerBoxPublicKeys[i],
				ServerBoxPrivateKeys[j])
		}
	}

	LeaderCertificate = ServerCertificates[0]
}
