#!/bin/sh -x
# $Id$
# 
# Script for generating a release
#

CVS='cvs-real -d hpa@terminus.zytor.com:/home/hpa/cvsroot'
MODULE=tftp-hpa

if [ -z "$1" ]; then
  echo "Usage: $0 release-id" 1>&2
  exit 1
fi

release="$1"
cvsrelease=$MODULE-`echo "$release" | tr '.' '_'`
releasedir=$MODULE-$release

echo $release > version
$CVS commit -m 'Update version for release' version

$CVS tag -F $cvsrelease

here=`pwd`

tmpdir=/var/tmp/release.$$
rm -rf $tmpdir
mkdir $tmpdir
cd $tmpdir
$CVS export -r $cvsrelease $MODULE
mv $MODULE $releasedir
cd $releasedir
make release
rm -f release.sh
cd ..
tar cvvf $here/../$releasedir.tar $releasedir
gzip -9 $here/../$releasedir.tar
