This directory contains certificates and keys for use with SSL in the sample applications. Certificates are issued by
our "Spring Security Test CA" certificate authority.

ca.pem     - the certificate authority's certificate.
server.jks - Java keystore containing the server certificate and privatekey. It Also contains the certificate authority
             file and this is used as both keystore and truststore for they jetty server when running the samples with
             the maven jetty plugin ("mvn jetty:run").

rod.p12, dianne.p12, scott.p12 are all certificate/key combinations for client authentication and can be installed in
your browser if you want to try out support for X.509 authentication.