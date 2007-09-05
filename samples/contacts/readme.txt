

The contacts application demonstrates the main Acegi Security features in action in a web application. Prior to version
1.0.5, the application was built into several separate WAR files, each using different features - X.509, CAS, LDAP etc.

In the interest of simplicity it has now been refactored into a single web application. The web application context is
loaded from /WEB-INF/applicationContext-acegi-security.xml. The other context files have been left in the WEB-INF
directory for reference but aren't used in the application.

To run the application, assuming you have checked out the source tree from subversion, run

mvn install

from the project root. Then run

mvn jetty:run

from the contacts sample directory. This should start the web application on port 8080 for you to try out.

$Id$