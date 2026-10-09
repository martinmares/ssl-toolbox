module github.com/martinmares/ssl-toolbox

go 1.26.0

replace software.sslmate.com/src/go-pkcs12 => ./third_party/go-pkcs12

require (
	github.com/pavlo-v-chernykh/keystore-go/v4 v4.5.0
	github.com/spf13/cobra v1.10.2
	go.yaml.in/yaml/v3 v3.0.5
	golang.org/x/term v0.46.0
	software.sslmate.com/src/go-pkcs12 v0.7.3
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	golang.org/x/crypto v0.11.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)
