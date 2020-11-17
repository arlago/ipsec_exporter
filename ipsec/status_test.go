package ipsec

import (
    "errors"
    "testing"
)

type dummyStatusProvider struct {
    returnString string
    returnError  error
}

func (d *dummyStatusProvider) statusOutput(tunnel connection) (string, error) {
    if d.returnError != nil {
        return "", d.returnError
    }
    return d.returnString, nil
}

func TestQueryStatus(t *testing.T) {
    tunnelName := "foo"
    configuration := &Configuration{
        tunnel: []connection{
            {name: tunnelName, ignored: false,},
        },
    }

    status := queryStatus(configuration, &dummyStatusProvider{returnString: `Status of IKE charon daemon (strongSwan 5.3.5, Linux 4.4.0-31-generic, x86_64):
    uptime: 18 days, since Jan 24 16:00:17 2019
    malloc: sbrk 1486848, mmap 0, used 343952, free 1142896
    worker threads: 11 of 16 idle, 5/0/0/0 working, job queue: 0/0/0/0, scheduled: 4
    loaded plugins: charon test-vectors aes rc2 sha1 sha2 md4 md5 random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl fips-prf gmp agent xcbc hmac gcm attr kernel-netlink resolve socket-default connmark stroke updown
  Listening IP addresses:
    10.0.1.10
    10.0.0.10
  Connections:
          foo:  10.0.0.10...137.37.37.37  IKEv2, dpddelay=30s
          foo:   local:  [117.17.17.17] uses pre-shared key authentication
          foo:   remote: [137.37.37.37] uses pre-shared key authentication
          foo:   child:  172.19.10.0/24 === 172.19.5.0/24 TUNNEL, dpdaction=restart
  Security Associations (1 up, 0 connecting):
          foo[21]: ESTABLISHED 16 hours ago, 10.0.0.10[117.17.17.17]...137.37.37.37[137.37.37.37]
          foo[21]: IKEv2 SPIs: b26da4ae5279684d_i* 7f5b0cfd45d5dc94_r, pre-shared key reauthentication in 7 hours
          foo[21]: IKE proposal: AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048
  foo{3}:  INSTALLED, TUNNEL, reqid 1, ESP SPIs: c96e6b17_i 34f71a54_o
  foo{3}:  AES_CBC_128/HMAC_SHA1_96, 0 bytes_i (0 pkts, 4s ago), 0 bytes_o, rekeying disabled
  foo{3}:   172.19.10.0/24 === 172.19.5.0/24
  foo{5}:  INSTALLED, TUNNEL, reqid 1, ESP SPIs: c96e6b17_i 34f71a54_o
  foo{5}:  AES_CBC_128/HMAC_SHA1_96, 319 bytes_i (1 pkt, 4s ago), 0 bytes_o, rekeying disabled
  foo{5}:   172.19.10.0/24 === 172.19.5.0/24
  foo{7}:  INSTALLED, TUNNEL, reqid 1, ESP SPIs: c96e6b17_i 34f71a54_o
  foo{7}:  AES_CBC_128/HMAC_SHA1_96, 0 bytes_i (0 pkts, 4s ago), 44 bytes_o (1 pkt, 1376s ago), rekeying disabled
  foo{7}:   172.19.10.0/24 === 172.19.5.0/24
  foo{9}:  INSTALLED, TUNNEL, reqid 1, ESP SPIs: c96e6b17_i 34f71a54_o
  foo{9}:  AES_CBC_128/HMAC_SHA1_96, 84 bytes_i (2 pkts, 4s ago), 0 bytes_o, rekeying disabled
  foo{9}:   172.19.10.0/24 === 172.19.5.0/24
  foo{11}:  INSTALLED, TUNNEL, reqid 1, ESP SPIs: c96e6b17_i 34f71a54_o
  foo{11}:  AES_CBC_128/HMAC_SHA1_96, 425 bytes_i (4 pkts, 4s ago), 168 bytes_o (4 pkts, 1376s ago), rekeying disabled
  foo{11}:   172.19.10.0/24 === 172.19.5.0/24
  foo{13}:  INSTALLED, TUNNEL, reqid 1, ESP SPIs: c96e6b17_i 34f71a54_o
  foo{13}:  AES_CBC_128/HMAC_SHA1_96, 40 bytes_i (1 pkt, 4s ago), 0 bytes_o, rekeying disabled
  foo{13}:   172.19.10.0/24 === 172.19.5.0/24
  foo{15}:  INSTALLED, TUNNEL, reqid 1, ESP SPIs: c96e6b17_i 34f71a54_o
  foo{15}:  AES_CBC_128/HMAC_SHA1_96, 0 bytes_i (0 pkts, 4s ago), 0 bytes_o, rekeying disabled
  foo{15}:   172.19.10.0/24 === 172.19.5.0/24
  foo{17}:  INSTALLED, TUNNEL, reqid 1, ESP SPIs: c96e6b17_i 34f71a54_o
  foo{17}:  AES_CBC_128/HMAC_SHA1_96, 44 bytes_i (1 pkt, 4s ago), 44 bytes_o (1 pkt, 1376s ago), rekeying disabled
  foo{17}:   172.19.10.0/24 === 172.19.5.0/24
  foo{19}:  INSTALLED, TUNNEL, reqid 1, ESP SPIs: c96e6b17_i 34f71a54_o
  foo{19}:  AES_CBC_128/HMAC_SHA1_96, 2291975 bytes_i (13262 pkts, 0s ago), 531970 bytes_o (12463 pkts, 0s ago), rekeying disabled
  foo{19}:   172.19.10.0/24 === 172.19.5.0/24
`})

    if status[tunnelName] == nil {
        t.Errorf("Expected a status for the tunnel named '%s'.", tunnelName)
        return
    }

    if !status[tunnelName].up {
        t.Errorf("Expected tunnel '%s' to be reported up.", tunnelName)
    }

    actualStatus := status[tunnelName].status
    if actualStatus != tunnelInstalled {
        t.Errorf("Expected tunnel '%s' to have status '%d', but has '%d'.", tunnelName, tunnelInstalled, actualStatus)
    }

    expectedBytesIn := 2292887
    actualBytesIn := status[tunnelName].bytesIn
    if actualBytesIn != expectedBytesIn {
        t.Errorf("Expected '%d' bytes In, but was '%d'", expectedBytesIn, actualBytesIn)
    }

    expectedBytesOut := 532226
    actualBytesOut := status[tunnelName].bytesOut
    if actualBytesOut != expectedBytesOut {
        t.Errorf("Expected '%d' bytes Out, but was '%d'", expectedBytesOut, actualBytesOut)
    }

    expectedPacketsIn := 13271
    actualPacketsIn := status[tunnelName].packetsIn
    if actualPacketsIn != expectedPacketsIn {
        t.Errorf("Expected '%d' packets In, but was '%d'", expectedPacketsIn, actualPacketsIn)
    }

    expectedPacketsOut := 12469
    actualPacketsOut := status[tunnelName].packetsOut
    if actualPacketsOut != expectedPacketsOut {
        t.Errorf("Expected '%d' packets Out, but was '%d'", expectedPacketsOut, actualPacketsOut)
    }
}

func TestQueryStatus_ignoredTunnel(t *testing.T) {
    tunnelName := "foo"
    configuration := &Configuration{
        tunnel: []connection{
            {name: tunnelName, ignored: true,},
        },
    }

    status := queryStatus(configuration, &dummyStatusProvider{returnString: ""})

    if status[tunnelName] == nil {
        t.Errorf("Expected a status for the tunnel named '%s'.", tunnelName)
        return
    }

    if !status[tunnelName].up {
        t.Errorf("Expected tunnel '%s' to be reported up.", tunnelName)
    }

    actualStatus := status[tunnelName].status
    if actualStatus != ignored {
        t.Errorf("Expected tunnel '%s' to have status '%d', but has '%d'.", tunnelName, ignored, actualStatus)
    }
}

func TestQueryStatus_errorInProvider(t *testing.T) {
    tunnelName := "foo"
    configuration := &Configuration{
        tunnel: []connection{
            {name: tunnelName, ignored: false,},
        },
    }

    status := queryStatus(configuration, &dummyStatusProvider{returnError: errors.New("doesn't matter")})

    if status[tunnelName] == nil {
        t.Errorf("Expected a status for the tunnel named '%s'.", tunnelName)
        return
    }

    if status[tunnelName].up {
        t.Errorf("Expected tunnel '%s' to be reported down.", tunnelName)
    }

    actualStatus := status[tunnelName].status
    if actualStatus != unknown {
        t.Errorf("Expected tunnel '%s' to have status '%d', but has '%d'.", tunnelName, unknown, actualStatus)
    }
}

func TestStatus_noMatch(t *testing.T) {
    input := "Security Associations (1 up, 0 connecting):\n	 no match"
    status := extractStatus([]byte(input))

    if status != down {
        t.Errorf("Expected tunnel to be 'down', but was state %d", status)
    }
}

func TestStatus_connectionUpTunnelMissing(t *testing.T) {
    input := "Security Associations (1 up, 0 connecting):\n  fancy[3]: ESTABLISHED 16 hours ago, 10.0.0.7[213.123.123.9]...212.93.93.93[212.93.93.93]\n	 fancy{134}:  REKEYED, TUNNEL, reqid 2, ESP in UDP SPIs: cc2e965d_i 6d01c0d7_o\n 	fancy{134}:   10.2.0.112/29 === 10.3.0.0/24"
    status := extractStatus([]byte(input))

    if status != connectionEstablished {
        t.Errorf("Expected tunnel to be 'connectionEstablished', but was state %d", status)
    }
}

func TestStatus_operational(t *testing.T) {
    input := "Security Associations (1 up, 0 connecting):\n  fancy[3]: ESTABLISHED 16 hours ago, 10.0.0.7[213.123.123.9]...212.93.93.93[212.93.93.93]\n	 fancy{134}:  INSTALLED, TUNNEL, reqid 2, ESP in UDP SPIs: cc2e965d_i 6d01c0d7_o\n 	fancy{134}:   10.2.0.112/29 === 10.3.0.0/24"
    status := extractStatus([]byte(input))

    if status != tunnelInstalled {
        t.Errorf("Expected tunnel to be 'tunnelInstalled', but was state %d", status)
    }
}

func TestExtractIntWithRegex(t *testing.T) {
    input := "A string to match 42."
    regex := `match ([0-9]+)`

    result := extractIntWithRegex(input, regex)

    if result != 42 {
        t.Errorf("Expected to match '42', but got '%d'", result)
    }
}

func TestExtractIntWithRegex_nonIntRegex(t *testing.T) {
    input := "A string to match 42."
    regex := `to ([a-z]+)`

    result := extractIntWithRegex(input, regex)

    if result != 0 {
        t.Errorf("Expected to fail and return '0', but got '%d'", result)
    }
}

func TestExtractIntWithRegex_noMatch(t *testing.T) {
    input := "A string to match 42."
    regex := `this wont match`

    result := extractIntWithRegex(input, regex)

    if result != 0 {
        t.Errorf("Expected to fail and return '0', but got '%d'", result)
    }
}
