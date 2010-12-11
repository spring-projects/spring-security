package org.springframework.security.web.util;

import org.springframework.util.PathMatcher;
import org.springframework.util.AntPathMatcher;

/**
 * Ant path strategy for URL matching.
 * <p>
 * If the path consists of the pattern {@code /**} or {@code **}, it is treated as a universal
 * match, which wil match any URL.
 * <p>
 * For all other cases, Spring's {@code AntPathMatcher} is used to perform the check for a match. See the Spring
 * documentation for this class for more information on the syntax details.
 *
 * @author Luke Taylor
 */
public class AntUrlPathMatcher implements UrlMatcher {
    private boolean requiresLowerCaseUrl = true;
    private PathMatcher pathMatcher = new AntPathMatcher();

    public AntUrlPathMatcher() {
        this(true);
    }

    public AntUrlPathMatcher(boolean requiresLowerCaseUrl) {
        this.requiresLowerCaseUrl = requiresLowerCaseUrl;
    }

    public Object compile(String path) {
        if (requiresLowerCaseUrl) {
            return path.toLowerCase();
        }

        return path;
    }

    public void setRequiresLowerCaseUrl(boolean requiresLowerCaseUrl) {
        this.requiresLowerCaseUrl = requiresLowerCaseUrl;
    }

    public boolean pathMatchesUrl(Object path, String url) {
        if ("/**".equals(path) || "**".equals(path)) {
            return true;
        }
        return pathMatcher.match((String)path, url);
    }

    public String getUniversalMatchPattern() {
        return "/**";
    }

    public boolean requiresLowerCaseUrl() {
        return requiresLowerCaseUrl;
    }

    public String toString() {
        return getClass().getName() + "[requiresLowerCase='" + requiresLowerCaseUrl + "']";
    }
}
