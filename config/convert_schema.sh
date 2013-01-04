#! /bin/sh

pushd src/main/resources/org/springframework/security/config/

echo "Converting rnc file to xsd ..."
java -jar ~/bin/trang.jar spring-security-3.2.rnc spring-security-3.2.xsd

echo "Applying XSL transformation to xsd ..."
xsltproc --output spring-security-3.2.xsd spring-security.xsl spring-security-3.2.xsd

popd