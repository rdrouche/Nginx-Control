module nginx-analyzer-go

go 1.24.7

replace golang.org/x/sys => github.com/golang/sys v0.30.0

replace golang.org/x/text => github.com/golang/text v0.21.0

require github.com/ncruces/go-sqlite3 v0.23.0

require (
	github.com/ncruces/julianday v1.0.0 // indirect
	github.com/tetratelabs/wazero v1.8.2
	golang.org/x/sys v0.30.0 // indirect
)
