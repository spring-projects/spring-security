#! /bin/sh
# $Id$
#
# See http://curl.netmirror.org/docs/httpscripting.html
#

set -o nounset
set -o errexit

ROOT_URL="http://localhost:8080"
CONTENT=response.txt
servlet_path=""

cleanup() {
  find . -name cookies.txt | xargs rm
  find . -name $CONTENT | xargs rm  
  find . -name runall.log | xargs rm
}

start_jetty()
{
  mvn -o jetty:run > runall.log &
  until (grep "Started Jetty Server" runall.log)
  do
    echo "- Waiting for server to start... -"
    sleep 3    
  done
}

stop_jetty() {
  kill $!
  until (grep "Jetty server exiting" runall.log)
  do
    echo "- Waiting for server to stop... -"
    sleep 2    
  done  
}


get() {
    if [ -z "$1" ]                           # Is parameter #1 zero length?
    then
      echo "- URL argument is required -"
      exit -1
    else
      echo "- GET \"$servlet_path$1\" -"
    fi
    
    curl -b cookies.txt -c cookies.txt -i -o $CONTENT "$servlet_path$1"
# We don't expect any 50x errors
    if grep -q "HTTP/1.1 50" $CONTENT
    then
      echo "$CONTENT"
      exit -1
    fi
    
    echo "- Done -"
}

post() {
    if [ $# -ne 2 ]                           # Is parameter #1 zero length?
    then
      echo "- Parameters and URL argument required -"
      exit -1
    else
      echo "- POST \"$servlet_path$2\" -"
    fi
    curl -b cookies.txt -c cookies.txt -i -o $CONTENT -d $1 "$servlet_path$2"
    echo "- Done -"    
}

assert() {
    if [ -z "$1" ]
    then
      echo "-'Expected text' argument is required.-"
      exit -1      
    fi
    
    if ! grep -q "$1" $CONTENT
    then
      echo "- '$1' was not found in response... -"
      exit -1
    fi
}

cleanup

#
# Run the tests
# 

cd tutorial
servlet_path="$ROOT_URL/tutorial"
echo "- Running tutorial app... -"
start_jetty
get /index.jsp
assert "Home Page"
assert "Your principal object is....: null"
get /secure/index.jsp
assert "HTTP/1.1 302 Found"
assert "Location:.*/spring_security_login"
get /spring_security_login
assert "Login with Username and Password"
get "/j_spring_security_check?j_username=rod&j_password=koala"
assert "HTTP/1.1 302 Found"
assert "Location:.*/spring_security_login?login_error"
get /spring_security_login?login_error
assert "Authentication method not supported: GET"
echo "- Logging in as Rod -"
post "j_username=rod&j_password=koala" "/j_spring_security_check"
assert "HTTP/1.1 302 Found"
assert "Location:.*/secure/index.jsp"
get /secure/index.jsp
assert "Secure Page"
assert "You are a supervisor!"
get "/listAccounts.html"
assert "Accounts" 
# Rod can break his overdraft limit
get "/post.html?id=1&amount=-200.00"
assert "Accounts"
get "/j_spring_security_logout"
echo "- Logging in as Peter -"
post "j_username=peter&j_password=opal" "/j_spring_security_check"
assert "HTTP/1.1 302 Found"
assert "Location:.*/tutorial/"
# Peter can't do anything
get "/post.html?id=4&amount=-20.00"
assert "HTTP/1.1 403 Access is denied"
get "/j_spring_security_logout"
echo "- Logging in as Dianne -"
post "j_username=dianne&j_password=emu" "/j_spring_security_check"
# Dianne can't exceed overdraft
get "/post.html?id=4&amount=-100.00"
assert "Accounts"
get "/post.html?id=4&amount=-20.00"
assert "HTTP/1.1 403 Access is denied"
get "/j_spring_security_logout"
stop_jetty

echo "- Running contacts app... -"
cd ../contacts
servlet_path="$ROOT_URL/contacts"
start_jetty
servlet_path="$ROOT_URL/contacts"
get /hello.htm
assert "Contacts Security Demo"
get /secure/index.htm
assert "HTTP/1.1 302 Found"
assert "Location:.*/login.jsp"
echo "- Logging in as Rod -"
post "j_username=rod&j_password=koala" "/j_spring_security_check"
assert "HTTP/1.1 302 Found"
get /secure/index.htm
assert "rod's Contacts"
assert "John Smith"
get "/secure/del.htm?contactId=1"
assert "Deleted"
assert "john@somewhere.com"
get /secure/index.htm
get "/secure/adminPermission.htm?contactId=4"
assert "Administer Permissions"
get "/secure/addPermission.htm?contactId=4"
assert "Add Permission"
post "recipient=bill&permission=16" "/secure/addPermission.htm?contactId=4"
get "/secure/adminPermission.htm?contactId=4"
assert "PrincipalSid\[bill\].*A....=16\]"
get /secure/index.htm
get "/j_spring_security_logout"
stop_jetty

echo "- Running ldap app... -"
cd ../ldap
start_jetty
servlet_path="$ROOT_URL/ldap"
get "/"
assert "Home Page"
get "/secure/"
assert "HTTP/1.1 302 Found"
assert "Location:.*/spring_security_login"
echo "- Logging in as Rod -"
post "j_username=rod&j_password=koala" "/j_spring_security_check"
assert "HTTP/1.1 302 Found"
assert "Location:.*/secure"
get "/secure/"
assert "Secure Page"
get "/j_spring_security_logout"
stop_jetty

echo "- Running preauth app... -"
cd ../preauth
servlet_path="$ROOT_URL/preauth"
start_jetty
get "/"
assert "HTTP/1.1 401 Unauthorized"
assert "WWW-Authenticate: Basic realm=\"Preauth Realm\""
curl -b cookies.txt -c cookies.txt -u rod:koala -i -o $CONTENT "$servlet_path/"
assert "Home Page"
get "/j_spring_security_logout"
stop_jetty


cd ../cas

if [[ -e ./server/cas-server-webapp-3.3.5.war ]]
then
   echo "Found cas server war. Running cas sample"
   cd server
   mvn jetty:run-war &
   SERVERPID=$!
   cd ../client
   start_jetty
   get "/"
   assert "Home Page"
   get "/secure/index.jsp"
   assert "HTTP/1.1 302 Found"
   assert "Location: https://localhost:9443/cas/login?service=https%3A%2F%2Flocalhost%3A8443%2Fcas-sample%2Fj_spring_cas_security_check"
   get "https://localhost:9443/cas/login?service=https%3A%2F%2Flocalhost%3A8443%2Fcas-sample%2Fj_spring_cas_security_check"
   kill $SERVERPID
   stop_jetty
fi

cd ..

cleanup

