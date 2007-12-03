
This directory contains some example certificates for the X.509 version of the contacts
application. They have all been generated using openssl with a demo certificate authority.
The password for all the files is "password"

- user.p12 is a pkcs12 file containing the client certificate and private key for
a user, and should be imported into your browser.

- server.p12 is a pkcs12 file containing a server certificate and private key.

- ca.jks is a java keystore file[1] containing the CA public certificate. This is used as
the trust store for the server to indicate which client certificates are valid.

The app has been tested in JBoss 3.2.7 (Tomcat 5.0) using the following configuration for
the connector:

  <!-- SSL/TLS Connector configuration -->
  <Connector port="8443" address="${jboss.bind.address}"
       maxThreads="100" minSpareThreads="2" maxSpareThreads="10"
       scheme="https" secure="true"
       sslProtocol = "TLS"
       clientAuth="want" keystoreFile="${jboss.server.home.dir}/conf/server.p12"
       keystoreType="PKCS12" keystorePass="password"
       truststoreFile="${jboss.server.home.dir}/conf/ca.jks"
       truststoreType="JKS" truststorePass="password"
    />

To try out the application, first get the server running with client authentication enabled.




[1] This was originally also a pkcs12 file. However I couldn't get tomcat to work with
it unless it contained the CA's private key as well as the certificate, which is obviously
not feasible. If anyone works out how to get Tomcat to work with a pkcs12 file containing
a single certificate, then please let me know.

$Id$
