## Spring Security
Spring Security provides security services for the [Spring IO Platform][]. Spring Security 3.1 requires Spring 3.0.3 as
a minimum and also requires Java 5.

For a detailed list of features and access to the latest release, please visit
[Spring projects][].

Spring Security is released under an Apache 2.0 license. See the accompanying
license.txt file.

## Downloading Artifacts
See [downloading Spring artifacts][] for Maven repository information.

## Documentation
Be sure to read the [Spring Security Reference].
Extensive JavaDoc for the Spring Security code is also available in the [Spring Security API Documentation][].

## Quick Start
We recommend you visit [Spring Security Reference][] and read the "Getting Started" page.

## Building from Source

Spring Security uses a [Gradle][]-based build system. In the instructions
below, [`./gradlew`][] is invoked from the root of the source tree and serves as
a cross-platform, self-contained bootstrap mechanism for the build.

### Prerequisites

[Git][] and the [JDK][JDK8 build]

Be sure that your `JAVA_HOME` environment variable points to the `jdk1.8.0` folder
extracted from the JDK download.

### Check out sources
`git clone git@github.com:spring-projects/spring-security.git`

### Install all spring-\* jars into your local Maven cache
`./gradlew install`

### Compile and test; build all jars, distribution zips, and docs
`./gradlew build`

... and discover more commands with `./gradlew tasks`. See also the [Gradle
build and release FAQ][].

## Getting Support
Check out the [Spring Security tags on Stack Overflow][]. [Commercial support][] is available too.

## Contributing
[Pull requests][] are welcome; see the [contributor guidelines][] for details.

[Spring IO Platform]: http://www.spring.io
[Spring projects]: http://spring.io/projects
[Spring Security Reference]: http://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/
[Spring Security API Documentation]: http://docs.spring.io/spring-security/site/docs/current/apidocs/
[downloading Spring artifacts]: https://github.com/spring-projects/spring-framework/wiki/Downloading-Spring-artifacts
[`./gradlew`]: http://vimeo.com/34436402
[Gradle]: http://gradle.org
[Gradle build and release FAQ]: https://github.com/spring-projects/spring-framework/wiki/Gradle-build-and-release-FAQ
[Git]: http://help.github.com/set-up-git-redirect
[JDK8 build]: http://www.oracle.com/technetwork/java/javase/downloads
[Spring Security tags on Stack Overflow]: http://stackoverflow.com/questions/tagged/spring-security
[Commercial support]: http://spring.io/services
[Pull requests]: http://help.github.com/send-pull-requests
[contributor guidelines]: https://github.com/spring-projects/spring-security/blob/master/CONTRIBUTING.md

