#! /bin/sh

pushd src/main/resources/org/springframework/security/config/

echo "Converting rnc file to xsd ..."
java -jar ~/bin/trang.jar spring-security-3.1.rnc spring-security-3.1.xsd

echo "Applying XSL transformation to xsd ..."
xsltproc --output spring-security-3.1.xsd spring-security.xsl spring-security-3.1.xsd

popd