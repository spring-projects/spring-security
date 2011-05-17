package org.springframework.security.core;

import static org.junit.Assert.assertEquals;

import org.junit.*;

/**
 * Checks that the embedded version information is up to date.
 *
 * @author Luke Taylor
 */
public class SpringSecurityCoreVersionTests {

    @Test
    public void springVersionIsUpToDate() throws Exception {
        // Property is set by the build script
        String springVersion = System.getProperty("springVersion");

        assertEquals(springVersion, SpringSecurityCoreVersion.MIN_SPRING_VERSION);
    }

    @Test
    public void serialVersionMajorAndMinorVersionMatchBuildVersion() throws Exception {
        String version = System.getProperty("springSecurityVersion");

        // Strip patch version
        String serialVersion = String.valueOf(SpringSecurityCoreVersion.SERIAL_VERSION_UID).substring(0,2);

        assertEquals(version.charAt(0), serialVersion.charAt(0));
        assertEquals(version.charAt(2), serialVersion.charAt(1));

    }
}
