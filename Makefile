build:
	echo "building binary"
	mkdir -p bin
	cd cmd/jarmscan/ && GOOS=linux CGO_ENABLED=0 go build -o ../../bin/jarmscan .
