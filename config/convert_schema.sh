#! /bin/sh

pushd src/main/resources/org/springframework/security/config/

echo "Converting rnc file to xsd ..."
java -jar ~/bin/trang.jar spring-security-3.0.rnc spring-security-3.0.xsd

echo "Applying XSL transformation to xsd ..."
xsltproc --output spring-security-3.0.xsd spring-security.xsl spring-security-3.0.xsd

popd