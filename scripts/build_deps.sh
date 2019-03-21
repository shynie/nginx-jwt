#!/bin/bash

set -o pipefail
set -e

script_dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd)
. $script_dir/common.sh

echo -e "${cyan}Fetching Lua depedencies...${no_color}"
load_dependency () {
    local target="$1"
    local user="$2"
    local repo="$3"
    local commit="$4"
    local required_sha1="$5"

    local actual_sha1=$(cat $target | openssl sha1 | sed 's/^.* //')

    if [ -e "$target" ] && [ "$required_sha1" == "$actual_sha1" ]; then
        echo -e "Dependency $target (with SHA-1 digest $required_sha1) already downloaded."
    else
        curl https://codeload.github.com/$user/$repo/tar.gz/$commit | tar -xz --strip 1 $repo-$commit/lib
    fi
}

load_dependency "lib/resty/jwt.lua" "SkyLothar" "lua-resty-jwt" "ee1d024071f872e2b5a66eaaf9aeaf86c5bab3ed" "a11b06765e11d9c3f3fb2f2ff1073152d5c51896"
load_dependency "lib/resty/hmac.lua" "jkeys089" "lua-resty-hmac" "67bff3fd6b7ce4f898b4c3deec7a1f6050ff9fc9" "44dffa232bdf20e9cf13fb37c23df089e4ae1ee2"
load_dependency "lib/basexx.lua" "aiq" "basexx" "514f46ceb9a8a867135856abf60aaacfd921d9b9" "da8efedf0d96a79a041eddfe45a6438ea4edf58b"
