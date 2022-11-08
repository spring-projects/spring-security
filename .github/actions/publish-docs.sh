#!/bin/bash

FROM=build/site
HOST="$1"
HOST_PATH="$2"
SSH_PRIVATE_KEY="$3"
SSH_KNOWN_HOST="$4"
SSH_PRIVATE_KEY_PATH="$HOME/.ssh/${GITHUB_REPOSITORY:-publish-docs}"

if [ "$#" -ne 4 ]; then
  echo -e "not enough arguments USAGE:\n\n$0 \$HOST \$HOST_PATH \$SSH_PRIVATE_KEY \$SSH_KNOWN_HOST\n\n" >&2
  exit 1
fi

(
  set -e
  set -f
  install -m 600 -D /dev/null "$SSH_PRIVATE_KEY_PATH"
  echo "$SSH_PRIVATE_KEY" > "$SSH_PRIVATE_KEY_PATH"
  echo "$SSH_KNOWN_HOST" > ~/.ssh/known_hosts
  RSYNC_OPTS='-avz --delete'
  if [ -n "$BUILD_REFNAME" ]; then
    RSYNC_OPTS="-n $RSYNC_OPTS$(find $FROM -mindepth 1 -maxdepth 1 \! -name 404.html \! -name '.*' -type f -printf ' --include /%P')"
    RSYNC_OPTS="$RSYNC_OPTS$(find $FROM -mindepth 1 -maxdepth 1 -type d \! -name _ -printf ' --include /%P --include /%P/**') --exclude **"
  fi
  rsync $RSYNC_OPTS -e "ssh -i $SSH_PRIVATE_KEY_PATH" $FROM/ "$HOST:$HOST_PATH"
)
exit_code=$?

rm -f "$SSH_PRIVATE_KEY_PATH"

exit $exit_code
