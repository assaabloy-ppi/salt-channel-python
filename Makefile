.DEFAULT_GOAL := help
.PHONY: any

help: Makefile
	@echo "\nUsage: make <target>"
	@echo "\twhere <target> is one of the following:\n"
	@grep -E '^[0-9a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST)  | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
	@echo

test: ## Run all unittests
	_virtualenv/bin/python3 setup.py test

clean: ## Project cleanup
	py3clean .
	rm -f MANIFEST
	rm -rf build dist

benchmark_saltlib: ## Run SaltLib benchmarking suite
	_virtualenv/bin/python3 setup.py benchmark_saltlib

bootstrap: _virtualenv ## Initialize virtual environment
#ifneq ($(wildcard test-requirements.txt),)
	_virtualenv/bin/pip3 install -r test-requirements.txt
#endif
	_virtualenv/bin/pip3 install -e .
	make clean

activate:  ## Activate virtual environment if inactive
	python3 _virtualenv/bin/activate_this.py

_virtualenv:
	virtualenv _virtualenv
	_virtualenv/bin/pip3 install --upgrade pip
	_virtualenv/bin/pip3 install --upgrade setuptools

run_simple_echo_session: ## Run session 'dev/SimpleEchoSession.py' within local client & server connected with ByteChannel
	_virtualenv/bin/python3 -m saltchannel.dev.run_session  MpClientServerPair  SimpleEchoSession

run_simple_echo_session_a: ## Run asyncio version of 'run_simple_echo_session' target
	_virtualenv/bin/python3 -m saltchannel.dev.run_session_a

run_example_session1: ## Run 'dev/example_session1.py' to dump basic hansdhake data
	_virtualenv/bin/python3 -m saltchannel.dev.example_session1

run_example_session1_a: ## Run 'dev/example_session1_a.py' to dump basic hansdhake data (async!)
	_virtualenv/bin/python3 -m saltchannel.dev.example_session1_a

run_example_session2: ## Run 'dev/example_session2.py' to dump A1-A2 protocol
	_virtualenv/bin/python3 -m saltchannel.dev.example_session2

run_example_session2_a: ## Run 'dev/example_session2_a.py' to dump A1-A2 protocol
	_virtualenv/bin/python3 -m saltchannel.dev.example_session2_a
