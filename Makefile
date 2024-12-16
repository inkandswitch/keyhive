.PHONY: test
test: # run tests
	cargo test --features test_utils

.PHONY: test-until-fails
test-until-fail:
	./test-until-fail
