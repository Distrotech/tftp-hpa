#!/bin/sh -x
# $Id$
# 
# Script for generating a release
#

CVS='cvs -d hpa@terminus.zytor.com:/home/hpa/cvsroot'
MODULE=tftp
PACKAGE=tftp-hpa

if [ -z "$1" ]; then
  echo "Usage: $0 release-id" 1>&2
  exit 1
fi

release="$1"
cvsrelease=$PACKAGE-`echo "$release" | tr '.' '_'`
releasedir=$PACKAGE-$release

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
tar cvvf $releasedir.tar $releasedir
gzip -9 $releasedir.tar
mv -f $releasedir.tar.gz $here/..
cd ..
rm -rf $tmpdir
