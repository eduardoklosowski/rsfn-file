# Project

PACKAGE_NAME := rsfn-file
EXECUTABLE_NAME := rsfnfile

.DEFAULT_GOAL := build


# Build

.PHONY: build dist/$(EXECUTABLE_NAME)

build: dist/$(EXECUTABLE_NAME)  ## Compila executável para distribuição

dist/$(EXECUTABLE_NAME):
	mkdir -p dist
	cargo build --package=$(PACKAGE_NAME) --bin=$(EXECUTABLE_NAME) --release
	cp target/release/$(EXECUTABLE_NAME) $@
	strip $@


# Formmat

.PHONY: fmt

fmt:  ## Formata o código do projeto
	cargo fmt --all


# Lint

.PHONY: lint

lint: lint-cargo-fmt lint-cargo-check lint-clippy  ## Executa verificações no projeto

lint-cargo-fmt:  ## Verifica se o código está formatado
	cargo fmt --all --check

lint-cargo-check:  ## Verifica se não existe nenhum erro do rust
	cargo check --locked --all-targets

lint-clippy:  ## Verifica erros comuns e melhorias no código rust
	cargo clippy --locked --all-targets -- -Dwarnings


# Test

.PHONY: test test-cargo

test: test-cargo  ## Executa testes do projeto

test-cargo:  ## Executa testes do rust
	cargo test --locked --quiet


# Clean

.PHONY: clean clean-cargo clean-build

clean: clean-cargo clean-build  ## Limpa o projeto

clean-cargo:  ## Remove compilados do cargo
	cargo clean

clean-build:  ## Remove o executável compilado
	rm -rf dist


# Misc

.PHONY: help

help:
	@awk 'BEGIN {FS = ":.*## "} /^[A-Za-z\$$/].*:.*## / {printf "\033[36m%-25s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
