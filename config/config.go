package config

type Opt struct {
	OCSP string
	TSP  string
}

var Test = Opt{
	OCSP: "http://test.pki.gov.kz/ocsp/",
	TSP:  "http://test.pki.gov.kz/tsp/",
}

var Production = Opt{
	OCSP: "http://ocsp.pki.gov.kz",
	TSP:  "http://tsp.pki.gov.kz:80",
}

const LibName = "libkalkancryptwr-64.so"
