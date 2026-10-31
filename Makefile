.PHONY: test lint scenarios integration verify

PYTHON ?= python3
IMAGE  ?= ip_list_aggregator:test

test:
	$(PYTHON) -m unittest discover -s tests -v

lint:
	bash -n update_firewall_blocklist.sh
	bash -n tests/scenarios.sh
	bash -n tests/integration.sh
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck -S warning update_firewall_blocklist.sh tests/scenarios.sh tests/integration.sh; \
	else \
		echo "shellcheck not installed - skipped"; \
	fi

scenarios:
	bash tests/scenarios.sh

integration:
	docker build -t $(IMAGE) -f tests/Dockerfile .
	docker run --rm --privileged -v "$$PWD:/repo:ro" $(IMAGE) bash /repo/tests/integration.sh

verify: test lint scenarios
