#!/bin/sh -xe
# 
# Script for generating a release
#

PACKAGE=tftp-hpa

if [ -z "$1" ]; then
  echo "Usage: $0 release-id" 1>&2
  exit 1
fi

release="$1"
releasetag=$PACKAGE-$release
releasedir=$PACKAGE-$release

GIT_DIR=`cd "${GIT_DIR-.git}" && pwd`
export GIT_DIR

if [ `git diff --cached | wc -l` -ne 0 ]; then
    echo "$0: index not clean" 1>&2
    exit 1
fi

if [ x"$release" = x'test' ]; then
  release=`cat version`
  releasetag=HEAD
  releasedir=$PACKAGE-$release
else
  echo $release > version
  if [ `git diff version | wc -l` -ne 0 ]; then
    git add version
    git commit -m "Update version for release $release" version
  else
    git checkout version
  fi
  rm -f "$GIT_DIR"/refs/tags/$releasetag
  git tag -a -m "$releasetag" -f "$releasetag"
fi

here=`pwd`

tmpdir=/var/tmp/release.$$
rm -rf $tmpdir
mkdir -p $tmpdir
cd $tmpdir
mkdir -p $releasedir
git archive --format=tar $releasetag | tar -xf - -C $releasedir
cd $releasedir
make release
rm -f release.sh
cd ..
tar cvvf $releasedir.tar $releasedir
gzip -9 $releasedir.tar
mv -f $releasedir.tar.gz $here/..
cd ..
rm -rf $tmpdir
