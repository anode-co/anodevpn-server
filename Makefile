SHELL:=/bin/bash

.PHONY: help

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

build: ## Build a docker image named anodevpn-server
	docker build --tag anode-vpn-server .

start: ## Start anode-vpn
	docker run --detach --network host anodevpn-server

stop: ## Stop anode-vpn
	docker ps --all | \grep 'anodevpn-server' | awk '{print $$1}' | xargs -I{} docker rm --force {}