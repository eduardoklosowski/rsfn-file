#!/bin/bash

set -eux


# Bash Completions

mkdir -p ~/.local/share/bash-completion/completions
echo '. <(rustup completions bash rustup)' > ~/.local/share/bash-completion/completions/rustup
echo '. <(rustup completions bash cargo)' > ~/.local/share/bash-completion/completions/cargo
