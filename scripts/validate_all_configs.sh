#!/usr/bin/env bash
set -o nounset
set -o errexit
set -o pipefail
shopt -s dotglob

export KMS_KEY_ALIAS='alias/psm'
export AWS_DEFAULT_REGION='us-east-1'
python3 ./validate_all_configs.py --loglevel WARNING ./*json
