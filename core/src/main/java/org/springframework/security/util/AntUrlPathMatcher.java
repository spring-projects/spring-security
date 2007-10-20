package org.springframework.security.util;

import org.springframework.util.PathMatcher;
import org.springframework.util.AntPathMatcher;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Ant path strategy for URL matching.
 *
 * @author luke
 * @version $Id$
 */
public class AntUrlPathMatcher implements UrlMatcher {
    private static final Log logger = LogFactory.getLog(AntUrlPathMatcher.class);

    private boolean convertToLowercaseBeforeComparison = true;
    private PathMatcher pathMatcher = new AntPathMatcher();

    public Object compile(String path) {
        if (convertToLowercaseBeforeComparison) {
            return path.toLowerCase();
        }

        return path;
    }

    public void setConvertToLowercaseBeforeComparison(boolean convertToLowercaseBeforeComparison) {
        this.convertToLowercaseBeforeComparison = convertToLowercaseBeforeComparison;
    }

    public boolean pathMatchesUrl(Object path, String url) {
        if (convertToLowercaseBeforeComparison) {
            url = url.toLowerCase();
            if (logger.isDebugEnabled()) {
                logger.debug("Converted URL to lowercase, from: '" + url + "'; to: '" + url + "'");
            }
        }

        return pathMatcher.match((String)path, url);
    }

    public String getUniversalMatchPattern() {
        return "/**";
    }
}
