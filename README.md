# go-sensitive
Library for recursively, flexibly and conservatively handling sensitive data that needs to be masked before being printed or sent.


# Run all tests
go test ./...

# Run tests with verbose
go test -v ./...

# Run tests with coverage
go test -cover ./...

# Run tests for a specific package
go test -v ./masker

# Run integration tests
go test -v ./test