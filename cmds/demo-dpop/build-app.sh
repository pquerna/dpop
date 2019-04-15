#!/bin/bash

set -eo pipefail
set -x

# DemoDpop.app/
# └── Contents
#    ├── Info.plist
#    ├── MacOS
#    │   └── demo-dpop
#    └── Resources
#        └── icon.icns

BIN_PATH=${1}
CODESIGN_IDENTITY=${2}

DIR="${BASH_SOURCE%/*}"
if [[ ! -d "$DIR" ]]; then DIR="$PWD"; fi


cd ${DIR}
cd ..
cd ..

rm -rf dist

DISTDIR="dist/DemoDpop.app"

mkdir -p "${DISTDIR}"
mkdir -p "${DISTDIR}/Contents"
mkdir -p "${DISTDIR}/Contents/MacOS"
mkdir -p "${DISTDIR}/Contents/Resources"

cp -v "${BIN_PATH}" "${DISTDIR}/Contents/MacOS/demo-dpop"
cp -v "cmds/demo-dpop/icon.icns" "${DISTDIR}/Contents/Resources/icon.icns"
cp -v "cmds/demo-dpop/Info.plist" "${DISTDIR}/Contents/Info.plist"

codesign --entitlements "./cmds/demo-dpop/enclave-entitlement.xml" -fs "${CODESIGN_IDENTITY}" "${DISTDIR}/Contents/MacOS/demo-dpop"
codesign --entitlements "./cmds/demo-dpop/enclave-entitlement.xml" -fs "${CODESIGN_IDENTITY}" "${DISTDIR}"
