#!/bin/bash

set -eo pipefail

. ./venv/bin/activate

cd test

ansible-playbook playbook.yaml
