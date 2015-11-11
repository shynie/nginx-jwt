#!/usr/bin/env bash
version=$(cat version.txt)
message=$1

./build package

git tag -a $version -m $version
git push origin --tags

release_id=curl -X POST https://api.github.com/repos/auth0/nginx-jwt/releases -d "{\"tag_name\": \"v$version\", \"target_commitish\": \"master\", \"name\": \"v$version\", \"body\": \"$2\", \"draft\": true, \"prerelease\": false}" | jq '.["id"]'
curl -X POST -H "Content-Type: application/x-tar" https://uploads.github.com/repos/auth0/nginx-jwt/releases/${release_id}/assets?name=nginx-jwt-${version}.tar.gz

echo -e "You'll still need to login to github to publish this draft release ( https://github.com/auth0/nginx-jwt/releases/v$version ) !"
echo -e "Download Url: https://github.com/auth0/nginx-jwt/releases/download/v${version}/nginx-jwt-${version}.tar.gz"