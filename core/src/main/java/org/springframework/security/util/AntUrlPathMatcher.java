package org.springframework.security.util;

import org.springframework.util.PathMatcher;
import org.springframework.util.AntPathMatcher;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Ant path strategy for URL matching.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class AntUrlPathMatcher implements UrlMatcher {
    private static final Log logger = LogFactory.getLog(AntUrlPathMatcher.class);

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
        return pathMatcher.match((String)path, url);
    }

    public String getUniversalMatchPattern() {
        return "/**";
    }

    public boolean requiresLowerCaseUrl() {
        return requiresLowerCaseUrl;
    }
}
