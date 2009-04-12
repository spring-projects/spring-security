#! /bin/sh

cleanup() {
  find . -name runall.log | xargs rm
}

start_jetty()
{
  mvn -o jetty:run > runall.log &
  until (grep "Started Jetty Server" runall.log)
  do
    echo "Waiting for server to start..."
    sleep 3    
  done
}

stop_jetty() {
  kill $!
  until (grep "Jetty server exiting" runall.log)
  do
    echo "Waiting for server to stop..."
    sleep 2    
  done  
}

cleanup

cd tutorial
echo "Running tutorial app..."
start_jetty
curl http://localhost:8080/tutorial/
stop_jetty

echo "Running contacts app..."
cd ../contacts
start_jetty
curl http://localhost:8080/contacts/
stop_jetty

echo "Running ldap app..."
cd ../ldap
start_jetty
curl http://localhost:8080/ldap/
stop_jetty

echo "Running preauth app..."
cd ../preauth
start_jetty
curl http://localhost:8080/preauth/
stop_jetty


cd ../cas

if [[ -e ./server/cas-server-webapp-3.3.1.war ]]
then
   echo "Found cas server war. Running cas sample"
   cd server
   mvn jetty:run-war &
   SERVERPID=$!
   cd ../client
   start_jetty
   curl http://localhost:8080/cas-sample/
   kill $SERVERPID
   stop_jetty
fi

cleanup

