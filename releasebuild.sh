#! /bin/sh

# This script must be run from the project root directory
#
# Release Process.
#
# 1. Do clean check out of source from svn.
# 2. Set the version number in the pom.xml files of all the module
# 3. Set the correct spring version number in the pom.xml.
# 3a Set the same version number in this script
# 4. Commit the source with the changed version numbers and note the revision number.
# 5. Run this script to generate the artifacts and web site in the 'release' directory.
#
#



#
# Edit this release number before running. It is used to check jar names etc.
#
RELEASE_VERSION=1.0.5-SNAPSHOT

PROJ_DIR=`pwd`;
RELEASE_DIR=$PROJ_DIR/release
SITE_DIR=$RELEASE_DIR/site

echo "** Project directory is $PROJ_DIR"

SVN_REV=`svn info $PROJ_DIR | grep Revision | sed "s/Revision: //"`

echo "** Building from revision $SVN_REV"

#
# Check the sandbox builds with the current configuration
#

pushd sandbox

mvn clean test

if [ "$?" -ne 0 ]
then
  echo "Failed to build sandbox with current configuration."
  exit 1;
fi

popd


#
# Create the release directory if it doesn't already exist
#

if [[ -e $RELEASE_DIR ]]
then
   rm -Rf $RELEASE_DIR
fi

mkdir $RELEASE_DIR
mkdir $SITE_DIR

# run maven to generate jars

mvn clean install -DcreateChecksum=true

if [ "$?" -ne 0 ]
then
  echo "mvn install failed"
  exit 1;
fi

echo "** Generating site in $SITE_DIR".

mvn site docbkx:generate-html docbkx:generate-pdf site:deploy -DsiteDirectory=file://${SITE_DIR}

if [ "$?" -ne 0 ]
then
  echo "mvn site generation failed"
  exit 1;
fi

# Patch the module site files to point to the root css files, change names of oversized menus,
# remove dodgy standard maven text etc.
#

pushd $RELEASE_DIR/site

find . -name "*.html" -maxdepth 2 -mindepth 2 | xargs perl -i -p -e 's#\./css/#\.\./css/#;' \
   -e 's/Maven Surefire Report/Unit Tests/;' \
   -e 's/Cobertura Test Coverage/Test Coverage/;'
   -e 's/A successful project.*greatly appreciated\.//;' 


popd


# Assemble the required jar files

find . -name "*${RELEASE_VERSION}.jar" | grep -v WEB-INF | xargs -J % -n 1  cp % $RELEASE_DIR
find . -name "*${RELEASE_VERSION}.war" | xargs -J % -n 1  cp % $RELEASE_DIR

# Should be 9 archives - core, core-tiger, the adapters (cas, jboss, resin, jetty, catalina), tutorial and contacts wars.

pushd $RELEASE_DIR

NUM_JARS=`ls *.jar *.war | wc -l`

if [ "$NUM_JARS" -ne 9 ]
then
  echo "Expected 9 Jar files but found $NUM_JARS."
  exit 1
fi

# Create the signatures

for jar in $(ls *.jar *.war); do
  openssl sha1 < $jar > $jar.sha1
  openssl md5 < $jar > $jar.md5
done

popd


