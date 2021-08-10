.PHONY: build
build:
	go build -o dyndns

.PHONY: lint
lint: build
	gofmt -w . && go mod tidy && golangci-lint run .

.PHONY: run
run: build lint
	./dyndns
