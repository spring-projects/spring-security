===============================================================================
                   ACEGI SECURITY SYSTEM FOR SPRING - EXTRACTOR
===============================================================================

*** OVERVIEW ***

To compile container adapters, it is necessary to have classes from each
container on the classpath. Because container JAR files are usually quite
large, including them in the "with dependencies" release ZIPs would rapidly
bloat the file size.

Under this solution, the extractor Ant build file takes a container JAR file
and extracts only those classes required by the Acegi Security System for
Spring. The full container JARs will be provided by the relevant container at
deployment time.

Of course, the classes are extracted from specific versions of the container
JAR files. The resulting "extracted" JAR files (named in the format
container-extracted.jar), include in their manifest file various information
about the source JAR. A copy of the container license is also provided.

If you run a different container version than those the extracted JARs were
built from, you can create a build.properties that specifies your
source.dir.container. Running "ant extract-container" will then cause your
exact container JAR file to be used to build the extracted JAR, which will be
written to the Acegi Security System for Spring main lib directory. You can
then recompile the Acegi Security System for Spring and you should end up
with compatible versions.

Two unavoidable issues from doing this include your version might package
required classes differently (so the files referred to by the Ant build file
are incorrect) or your container JAR might implement different inheritance
orders, interface requirements or method signatures than those the Acegi
Security System for Spring was coded for. In such cases, please let us know or
contribute a patch that supports your container version.

*** THE "SOURCE" DIRECTORY ***

The "source" directory contains the full container JAR files that the
container-extracted.jar files are created from. We do not include these in the
"with dependencies" releases. If you need these files, please download them
from the container vendor sites (refer to project.properties for URLs) or
checkout the project from CVS.

$Id$
