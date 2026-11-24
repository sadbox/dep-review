#!/bin/sh
# Records the GitHub REST answers the tests replay, with the gh CLI (GET
# only). Public third-party repositories only: never record an answer from
# a private repository here.
#
# Each answer is cut down with jq to the fields the gatherer reads, plus a
# few that make the file readable. Nothing is edited by hand: what a test
# needs GitHub to have said differently, it overrides in the test itself.
# A 404 is recorded as <path>.404.json with GitHub's own body.
#
# The file name is the request path under github/, so the replay transport
# needs no table: GET repos/o/r/compare/A...B is github/repos/o/r/compare/A...B.json.
set -eu
out=$(dirname "$0")/github

rec() { # rec <path> <jq filter>
	mkdir -p "$out/$(dirname "$1")"
	rm -f "$out/$1.json" "$out/$1.404.json"
	if body=$(gh api "$1?per_page=1" 2>"$out/.err"); then
		printf '%s' "$body" | jq "$2" >"$out/$1.json"
	elif grep -q 'HTTP 404' "$out/.err"; then
		printf '%s' "$body" | jq . >"$out/$1.404.json"
	else
		cat "$out/.err" >&2
		exit 1
	fi
	rm -f "$out/.err"
}

repo='{id, full_name, default_branch, archived, owner: {id: .owner.id, login: .owner.login}}'
ref='{ref, object: {type: .object.type, sha: .object.sha}}'
tag='{tag, sha, object: {type: .object.type, sha: .object.sha}}'
compare='{status, ahead_by, behind_by, total_commits, base_commit: {sha: .base_commit.sha}, merge_base_commit: {sha: .merge_base_commit.sha}}'
release='{tag_name, draft, prerelease, immutable, published_at, created_at, target_commitish}'

# update <owner/repo> <old commit> <new tag> <new commit> <branch>...
# records everything one update asks: the repository, the new tag, the
# comparison with the old pin, the comparison with each branch, the release.
update() {
	r=$1 old=$2 newtag=$3 new=$4
	shift 4
	rec "repos/$r" "$repo"
	rec "repos/$r/git/ref/tags/$newtag" "$ref"
	rec "repos/$r/compare/$old...$new" "$compare"
	for branch in "$@"; do
		rec "repos/$r/compare/$branch...$new" "$compare"
	done
	rec "repos/$r/releases/tags/$newtag" "$release"
}

# actions/setup-go v7.0.0 -> v7.1.0: lightweight tag, immutable release.
update actions/setup-go b7ad1dad31e06c5925ef5d2fc7ad053ef454303e v7.1.0 d8cbb8045d7f43706b9177cceb36c1f91a6644d5 main

# actions/checkout v7.0.0 -> v7.0.1: the release is not immutable.
update actions/checkout 9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 v7.0.1 3d3c42e5aac5ba805825da76410c181273ba90b1 main

# actions/checkout v6.0.2 -> v6.1.0: released from releases/v6, not on main.
update actions/checkout de0fac2e4500dabe0009e67214ff5f5447ce83dd v6.1.0 d23441a48e516b6c34aea4fa41551a30e30af803 main releases/v6

# actions/checkout v6.0.2 -> v6.0.3: v6.0.3 is an annotated tag.
update actions/checkout de0fac2e4500dabe0009e67214ff5f5447ce83dd v6.0.3 df4cb1c069e1874edd31b4311f1884172cec0e10 main
rec repos/actions/checkout/git/tags/9f698171ed81b15d1823a05fc7211befd50c8ae0 "$tag"

# docker/login-action v4.7.0 -> v4.8.0: the default branch is master.
update docker/login-action 81c6f93d4bc991e510b342a00b419b3bb4efc5c6 v4.8.0 8aa5831fb8d48d8f76594c7ddde61ae58019f550 master

# A commit that exists only in a fork of actions/setup-go (16a9d454),
# asked about through the upstream repository. 65771601 is the upstream
# commit the fork branched from. GitHub answers "ahead" for
# 65771601...16a9d454 although upstream has no branch holding the commit;
# only the comparison with a branch shows it.
fork=16a9d454083ee9312d7daf7d05b8c1918425822b
rec "repos/actions/setup-go/compare/65771601fffb58bc9398f4840ef80fafd2de713e...$fork" "$compare"
rec "repos/actions/setup-go/compare/main...$fork" "$compare"
rec "repos/actions/setup-go/compare/releases/v7...$fork" "$compare"
