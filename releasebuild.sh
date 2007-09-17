#! /bin/sh

# This script must be run from the project root directory
#
# Release Process.
#
# 1.  Do clean check out of source from svn and note revision number.
# 2.  Switch to 1.4 JVM and run 'mvn test' from core directory.
# 3.  Set the version number in the pom.xml files of all the module.
# 3a. If doing a release rather than snapshot build, run "find . -name pom.xml | xargs grep SNAPSHOT" and make sure
#     there are no important snapshot dependencies.
# 3b. Set the same version number in this script.
# 4.  Set the correct spring version number in the pom.xml.
# 5.  Run this script to generate the artifacts and web site in the 'release' directory.
# 6.  Copy the archives and unpack them to check the contents.
# 7.  The archives are tar archives. Create zip versions from the contents and check the internal paths are Ok.
# 8.  Check the site looks Ok.
# 9.  Check the reference guide links in the site are valid and that images are shown and paths in HTML are relative.
# 10. Deploy the contacts and tutorial sample apps in Jetty and Tomcat and check they work.
# 11. Check there have been no further commits since checkout (svn update). If there have, go to 1.
# 12. Commit the source with the changed version numbers and note the revision number (should be 'build revision' + 1).
# 13. Update the pom file versions to the appropriate snapshot version, do a grep to make sure none have been missed
#     and commit them.
# 14. Upload the site to acegisecurity.org (or wherever).
# 15. scp the release archives to shell.sf.net. Check md5 matches to make sure transfer was OK.
# 16. ftp them to the sourceforge upload server, uploads.sourceforge.net.
#
#

########################################################################################################################
#
# Edit this release number before running. It is used to check jar names etc.
#
########################################################################################################################

RELEASE_VERSION=2.0-SNAPSHOT

# Project Name. Used for creating the archives.
PROJECT_NAME=acegi-security

PROJ_DIR=`pwd`;
RELEASE_DIR=$PROJ_DIR/$PROJECT_NAME-$RELEASE_VERSION
SITE_DIR=$RELEASE_DIR/docs

echo "** Project directory is $PROJ_DIR"

SVN_REV=`svn info $PROJ_DIR | grep Revision | sed "s/Revision: //"`

echo "** Building from revision $SVN_REV"

########################################################################################################################
#
# Create the release directory
#
########################################################################################################################

if [[ -e $RELEASE_DIR ]]
then
   echo "Deleting $RELEASE_DIR."
   rm -Rf $RELEASE_DIR
fi

mkdir $RELEASE_DIR
mkdir $SITE_DIR

########################################################################################################################
#
# run maven to generate jars
#
########################################################################################################################

mvn clean install -DcreateChecksum=true

if [ "$?" -ne 0 ]
then
  echo "mvn install failed"
  exit 1;
fi

########################################################################################################################
#
# Check the sandbox builds with the current configuration
#
########################################################################################################################

pushd sandbox

mvn clean test

if [ "$?" -ne 0 ]
then
  echo "Failed to build sandbox with current configuration."
  exit 1;
fi

popd

########################################################################################################################
#
# Generate Maven Web Site and Process Docbook Source.
#
########################################################################################################################

echo "** Generating site in $SITE_DIR".

mvn site site:deploy -DsiteDirectory=file://${SITE_DIR}

if [ "$?" -ne 0 ]
then
  echo "mvn site generation failed"
  exit 1;
fi

########################################################################################################################
#
# Patch the module site files to point to the root css files, change names of oversized menus,
# remove dodgy standard maven text etc.
#
########################################################################################################################

pushd $SITE_DIR

find . -maxdepth 2 -mindepth 2 -name "*.html" | xargs perl -i -p -e 's#\./css/#\.\./css/#;' \
   -e 's/Maven Surefire Report/Unit Tests/;' \
   -e 's/Cobertura Test Coverage/Test Coverage/;' \
   -e 's/A successful project.*greatly appreciated\.//;'

find . -maxdepth 3 -mindepth 3 -name "*.html" | xargs perl -i -p -e 's#\./css/#\.\./\.\./css/#;'

popd

########################################################################################################################
#
# Assemble the required jar files, make sure there are the expected number and produce signatures.
#
########################################################################################################################


find . -name "*${RELEASE_VERSION}.jar" | grep -v WEB-INF | xargs -I % -n 1  cp % $RELEASE_DIR
find . -name "*${RELEASE_VERSION}.war" | xargs -I % -n 1  cp % $RELEASE_DIR

# Should be 10 archives - core, core-tiger, the adapters (cas, jboss, resin, jetty, catalina), ntlm, tutorial and contacts wars.

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

########################################################################################################################
#
# Build the release archives.
#
########################################################################################################################

# Get rid of mac DS_Store files.

find . -name .DS_Store -exec rm "{}" ";"

cp notice.txt readme.txt license.txt $RELEASE_DIR

# Create main archive

ls $RELEASE_DIR | grep -v sha | grep -v md5 | xargs tar -cjf $PROJECT_NAME-$RELEASE_VERSION.tar.bz2 -C $RELEASE_DIR

# Create source archive

tar --exclude='*/.svn' -cjf $PROJECT_NAME-$RELEASE_VERSION-src.tar.bz2 notice.txt src-readme.txt license.txt \
    -C core/src/main/java/ org \
    -C ${PROJ_DIR}/core-tiger/main/java org \
    -C ${PROJ_DIR}/adapters/jetty/main/java org \
    -C ${PROJ_DIR}/adapters/jboss/main/java org \
    -C ${PROJ_DIR}/adapters/resin/main/java org \
    -C ${PROJ_DIR}/adapters/cas/main/java org \
    -C ${PROJ_DIR}/adapters/catalina/main/java org    



