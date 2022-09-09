#!/bin/bash

HOST="$1"
HOST_PATH="$2"
SSH_PRIVATE_KEY="$3"
SSH_KNOWN_HOST="$4"
SSH_PRIVATE_KEY_PATH="$HOME/.ssh/${GITHUB_REPOSITORY:-publish-docs}"

if [ "$#" -ne 4 ]; then
  echo -e "not enough arguments USAGE:\n\n$0 \$HOST \$HOST_PATH \$SSH_PRIVATE_KEY \$SSH_KNOWN_HOST\n\n" >&2
  exit 1
fi

install -m 600 -D /dev/null "$SSH_PRIVATE_KEY_PATH"
echo "$SSH_PRIVATE_KEY" > "$SSH_PRIVATE_KEY_PATH"
echo "$SSH_KNOWN_HOST" > ~/.ssh/known_hosts
rsync --delete -avze "ssh -i $SSH_PRIVATE_KEY_PATH" build/site/ "$HOST:$HOST_PATH"
rm -f "$SSH_PRIVATE_KEY_PATH"
