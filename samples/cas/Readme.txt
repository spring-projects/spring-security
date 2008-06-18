There are two subdirectories in this project;

server - this is not a real maven sub-project in the sense that it builds anything. It is just here to allow you to
         conveniently run the CAS server using the maven Jetty plugin with our preconfigured SSL certificates.

client - this contains the actual sample web application which uses the cas server for authentication. It uses the same
         certificates. In practice, the CAS server would likely be running on a different machine and both client and
         server would have different certificates issued to the server hostname.

Running the CAS Server
-----------------------

You first need to download the CAS server 3.2.1 distribution from

http://www.ja-sig.org/products/cas/downloads/index.html

You only need the modules/cas-server-webapp-3.2.1.war web application file from the distribution. Copy this to the
"server" directory inside the one that contains this readme file (i.e. copy it to samples/cas/server).

You can then run the CAS server (from the same) by executing the maven command

mvn jetty:run-war

This will start the server on

https://localhost:9443/cas

If you point your browser at this URL, you should see the CAS login screen.


Running the Client Application
-------------------------------

Leave the server running and start up a separate command window to run the sample application. Change to the directory
samples/cas/client and execute the command

mvn jetty:run


This should start the sample application on

http://localhost:8080/cas-sample/

Try to access the secure page (as with the other samples) and you should be redirected to the CAS server to log in. Note
that the sample authentication module that comes with the CAS server webapp will authenticate any user whose password
matches the username. So you have to log in here as rod/rod, dianne/dianne etc. Obviously the usernames must still match
those listed in the application's user-service. 


$Id$



