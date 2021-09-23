REPOSITORY_REF="$1"
TOKEN="$2"

curl -H "Accept: application/vnd.github.everest-preview+json" -H "Authorization: token ${TOKEN}" --request POST  --data '{"event_type": "request-build"}' https://api.github.com/repos/${REPOSITORY_REF}/dispatches
echo "Requested Build for $REPOSITORY_REF"