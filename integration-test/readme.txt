===============================================================================
               ACEGI SECURITY SYSTEM FOR SPRING - INTEGRATION TESTS
===============================================================================

This directory allows execution of "in container" integration tests. To run
the tests, the original distribution files for various containers are required
to be placed into the containers directory. These are not included in CVS or 
ZIP releases due to their large size.

To execute these tests:

1. The following files should be placed into the containers directory:

   Jetty-4.2.18-all.zip         (see http://mortbay.jetty.org)
   jakarta-tomcat-5-0.19.zip    (see http://jakarta.apache.org/tomcat)
   jboss-3.2.3.zip              (see http://www.jboss.org)

2. Shutdown any container or service bound to port 8080.

3. Run "ant tests" (you can safely ignore the console output).

4. Review the reports directory and confirm each container passed all tests.

$Id$
