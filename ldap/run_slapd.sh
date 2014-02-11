#! /bin/sh

rm -Rf build/openldap
mkdir -p build/openldap
/usr/libexec/slapd -h ldap://localhost:22389 -d -1 -f slapd.conf &
sleep 3
ldapadd -h localhost -p 22389 -D cn=admin,dc=springsource,dc=com -w password -x -f openldaptest.ldif
