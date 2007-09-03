#! /bin/sh

# This script must be run from the project root directory

# Edit this release number before running. It is used to check jar names etc.
RELEASE_VERSION=1.0.5-SNAPSHOT

PROJ_DIR=`pwd`;
RELEASE_DIR=$PROJ_DIR/release
SITE_DIR=$RELEASE_DIR/site

echo "** Project directory is $PROJ_DIR"

SVN_REV=`svn info $PROJ_DIR | grep Revision | sed "s/Revision: //"`

echo "** Building from revision $SVN_REV"


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

# Patch the module site files to point to the correct css file

pushd $RELEASE_DIR/site

find . -name "*.html" -maxdepth 2 -mindepth 2 | xargs perl -i -p -e 's#\./css/site\.css#\.\./css/site\.css#'

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


