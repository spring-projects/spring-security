package org.springframework.security.core;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.SpringVersion;

/**
 * Internal class used for checking version compatibility in a deployed application.
 *
 * @author Luke Taylor
 * @author Rob Winch
 */
public class SpringSecurityCoreVersion {
    private static final String DISABLE_CHECKS = SpringSecurityCoreVersion.class.getName().concat(".DISABLE_CHECKS");

    private static final Log logger = LogFactory.getLog(SpringSecurityCoreVersion.class);

    /**
     * Global Serialization value for Spring Security classes.
     *
     * N.B. Classes are not intended to be serializable between different versions.
     * See SEC-1709 for why we still need a serial version.
     */
    public static final long SERIAL_VERSION_UID = 320L;

    static final String SPRING_MAJOR_VERSION = "3";

    static final String MIN_SPRING_VERSION = "3.2.4.RELEASE";

    static {
        performVersionChecks();
    }

    public static String getVersion() {
        Package pkg = SpringSecurityCoreVersion.class.getPackage();
        return (pkg != null ? pkg.getImplementationVersion() : null);
    }

    /**
     * Performs version checks
     */
    private static void performVersionChecks() {
        // Check Spring Compatibility
        String springVersion = SpringVersion.getVersion();
        String version = getVersion();

        if(disableChecks(springVersion, version)) {
            return;
        }

        logger.info("You are running with Spring Security Core " + version);
        if (!springVersion.startsWith(SPRING_MAJOR_VERSION)) {
            logger.warn("*** Spring Major version '" + SPRING_MAJOR_VERSION +
                    "' expected, but you are running with version: " + springVersion +
                    ". Please check your classpath for unwanted jar files.");
        }

        if (springVersion.compareTo(MIN_SPRING_VERSION) < 0) {
            logger.warn("**** You are advised to use Spring " + MIN_SPRING_VERSION +
                    " or later with this version. You are running: " + springVersion);
        }
    }

    private static boolean disableChecks(String springVersion, String springSecurityVersion) {
        if(springVersion == null || springVersion.equals(springSecurityVersion)) {
            return true;
        }
        return Boolean.getBoolean(DISABLE_CHECKS);
    }
}
