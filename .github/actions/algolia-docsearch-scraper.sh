#!/bin/bash

###
# Docs
# config.json https://docsearch.algolia.com/docs/config-file
# Run the crawler https://docsearch.algolia.com/docs/run-your-own/#run-the-crawl-from-the-docker-image

### USAGE
if [ "$#" -ne 3 ]; then
  echo -e "not enough arguments USAGE:\n\n$0 \$ALGOLIA_APPLICATION_ID \$ALGOLIA_API_KEY \$CONFIG_FILE\n\n" >&2
  exit 1
fi

# Script Parameters
APPLICATION_ID=$1
API_KEY=$2
CONFIG_FILE=$3

#### Script
script_dir=$(dirname $0)
docker run -e "APPLICATION_ID=$APPLICATION_ID" -e "API_KEY=$API_KEY" -e "CONFIG=$(cat $CONFIG_FILE | jq -r tostring)" algolia/docsearch-scraper
