package org.springframework.security.core;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.SpringVersion;

/**
 * Internal class used for checking version compatibility in a deployed application.
 *
 * @author Luke Taylor
 */
public class SpringSecurityCoreVersion {
    private static final Log logger = LogFactory.getLog(SpringSecurityCoreVersion.class);

    /**
     * Global Serialization value for Spring Security classes.
     *
     * N.B. Classes are not intended to be serializable between different versions.
     * See SEC-1709 for why we still need a serial version.
     */
    public static final long SERIAL_VERSION_UID = 310L;

    static {
        // Check Spring Compatibility
        String springVersion = SpringVersion.getVersion();
        String version = getVersion();

        if (springVersion != null) {
            logger.info("You are running with Spring Security Core " + version);
            if (!springVersion.startsWith("3")) {
                logger.error("Spring Major version '3' expected, but you are running with version: "
                        + springVersion + ". Please check your classpath for unwanted jar files.");
            }

            if (springVersion.compareTo("3.0.5") < 0) {
                logger.warn("You are advised to use Spring 3.0.5 or later with this version. You are running: " +
                    springVersion);
            }
        }
    }

    public static String getVersion() {
        Package pkg = SpringSecurityCoreVersion.class.getPackage();
        return (pkg != null ? pkg.getImplementationVersion() : null);
    }
}
