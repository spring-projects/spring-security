To run a CAS server and client application, just execute the command

./gradlew cas

from the project root directory. You should then be able to point your browser at

https://localhost:8443/cas/

to view the sample application. On attempting to access a secure page,
you'll be redirected to the CAS server where you can log in with one of
the usernames from the sample application context (enter the username in the
password field too, to authenticate to CAS in testing mode).
