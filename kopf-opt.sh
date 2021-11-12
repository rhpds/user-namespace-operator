#!/bin/sh
KOPF_OPTIONS="--log-format=json"

# Do not attempt to coordinate with other kopf operators.
KOPF_STANDALONE=true
