#!/bin/bash

HOST="$1"
HOST_PATH="$2"
SSH_PRIVATE_KEY="$3"
SSH_KNOWN_HOST="$4"


if [ "$#" -ne 4 ]; then
  echo -e "not enough arguments USAGE:\n\n$0 \$HOST \$HOST_PATH \$SSH_PRIVATE_KEY \$SSH_KNOWN_HOSTS \n\n" >&2
  exit 1
fi

# Use a non-default path to avoid overriding when testing locally
SSH_PRIVATE_KEY_PATH=~/.ssh/github-actions-docs
install -m 600 -D /dev/null "$SSH_PRIVATE_KEY_PATH"
echo "$SSH_PRIVATE_KEY" > "$SSH_PRIVATE_KEY_PATH"
echo "$SSH_KNOWN_HOST" > ~/.ssh/known_hosts
rsync --delete -avze "ssh -i $SSH_PRIVATE_KEY_PATH" docs/build/site/ "$HOST:$HOST_PATH"
rm -f "$SSH_PRIVATE_KEY_PATH"
