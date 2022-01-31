
.PHONY: all
all: test test_coverage
	
.PHONY: test
test:
	go test

.PHONY: test_coverage
test_coverage:
	go test `go list ./... | grep -v cmd` -coverprofile=coverage.txt -covermode=atomic
