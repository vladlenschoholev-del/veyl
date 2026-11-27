.PHONY: build-wasm verify run

build-wasm:
	./scripts/build-and-run.sh build-wasm

verify:
	./scripts/build-and-run.sh verify

run:
	./scripts/build-and-run.sh run
