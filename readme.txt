===============================================================================
              ACEGI SECURITY SYSTEM FOR SPRING - README FILE
===============================================================================

-------------------------------------------------------------------------------
OVERVIEW
-------------------------------------------------------------------------------

The Acegi Security System for Spring provides security services for 
The Spring Framework (http://www.springframework.org).

For a detailed list of features and access to the latest release, please visit
http://acegisecurity.sourceforge.net.

-------------------------------------------------------------------------------
ANT HELP
-------------------------------------------------------------------------------

Acegi Security includes several Apache Ant build.xml files. This eases Clover
integration and use of JUnit from the command line. We recommend you use the
provided build.bat or build.sh script (as appropriate to your platform).

With Windows, run the main build file "tests" target like this:
  ant tests

With Windows, run the Contacts sample "warfile" target like this:
  ant -buildfile samples\contacts\build.xml warfile

With Linux/Unix, run the main build file "tests" target like this:
  ./ant.sh tests

With Linux/Unix, run the Contacts sample "warfile" target like this:
  ./ant.sh -buildfile samples/contacts/build.xml warfile

Each example should be run from the root of the Acegi Security project
directory.

-------------------------------------------------------------------------------
QUICK START
-------------------------------------------------------------------------------

Copy samples/contact/dist/contacts.war into your container webapps directory.
Then visit http://localhost:8080/contacts/ and click "Manage". The Acegi
Security System for Spring secures this small application by protecting both
the method invocations of business objects, and also the HTTP URLs.

-------------------------------------------------------------------------------
DOCUMENTATION
-------------------------------------------------------------------------------

Please refer to the Reference Guide, which is located in the docs/reference
directory. In addition, JavaDocs are located in the docs/api directory.

-------------------------------------------------------------------------------
ADDING ACEGI SECURITY TO YOUR OWN APPLICATION
-------------------------------------------------------------------------------

Take a look in samples/quick-start. There we give you the fragments to add to
your existing web.xml and applicationContext.xml, along with a couple of files
that need to be added to your WAR file.

-------------------------------------------------------------------------------
OBTAINING SUPPORT
-------------------------------------------------------------------------------

If you need any help, please post a question on the Spring Users mailing list.

If you start using Acegi Security in your project, please consider joining
the acegisecurity-developer mailing list. This is currently the best way to
keep informed about the project's status and provide feedback in design 
discussions. You can join at:

  https://lists.sourceforge.net/lists/listinfo/acegisecurity-developer.

Links to mailing list archives and other useful resources are available from
http://acegisecurity.sourceforge.net.


$Id$
