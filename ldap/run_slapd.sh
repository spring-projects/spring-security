#! /bin/sh

rm -Rf target/openldap
mkdir -p target/openldap
/opt/local/libexec/slapd -h ldap://localhost:22389 -d -1 -f slapd.conf &
sleep 2
ldapadd -h localhost -p 22389 -D cn=admin,dc=springsource,dc=com -w password -x -f openldaptest.ldif