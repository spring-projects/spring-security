#! /bin/sh

pushd src/main/resources/org/springframework/security/config/

echo "Converting rnc file to xsd ..."
java -jar ~/bin/trang.jar spring-security-2.0.6.rnc spring-security-2.0.6.xsd

echo "Applying XSL transformation to xsd ..."
xsltproc --output spring-security-2.0.6.xsd spring-security.xsl spring-security-2.0.6.xsd

popd