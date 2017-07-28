.DEFAULT_GOAL := help
.PHONY: help test clean bootstrap run_echo_session asyncrun_echo_session

help: Makefile
	@echo "\nUsage: make <target>"
	@echo "\twhere <target> is one of the following:\n"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST)  | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
	@echo

test: ## Run all unittests
	python3 setup.py test

clean: ## Project cleanup
	rm -f MANIFEST
	rm -rf build dist

benchmark_saltlib: ## Run SaltLib benchmarking suite
	python3 setup.py benchmark_saltlib



bootstrap: _virtualenv
	_virtualenv/bin/pip3 install -e .
ifneq ($(wildcard test-requirements.txt),)
	_virtualenv/bin/pip3 install -r test-requirements.txt
endif
	make clean

_virtualenv:
	virtualenv _virtualenv
	_virtualenv/bin/pip3 install --upgrade pip
	_virtualenv/bin/pip3 install --upgrade setuptools

run_simple_echo_session: ## Run session 'dev/SimpleEchoSession.py' within local client & server connected with ByteChannel
	python3 -m saltchannel.dev.run_session  MpClientServerPair  SimpleEchoSession

run_simple_echo_session_a: ## Run asyncio version of 'run_simple_echo_session' target
	python3 -m saltchannel.dev.run_session_a