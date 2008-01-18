package org.springframework.security.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.regex.Pattern;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class RegexUrlPathMatcher implements UrlMatcher {
    private static final Log logger = LogFactory.getLog(RegexUrlPathMatcher.class);

    private boolean requiresLowerCaseUrl = false;

    public Object compile(String path) {
        return Pattern.compile(path);
    }

    public void setRequiresLowerCaseUrl(boolean requiresLowerCaseUrl) {
        this.requiresLowerCaseUrl = requiresLowerCaseUrl;
    }

    public boolean pathMatchesUrl(Object compiledPath, String url) {
        Pattern pattern = (Pattern)compiledPath;

        return pattern.matcher(url).matches();
    }

    public String getUniversalMatchPattern() {
        return "/.*";
    }

    public boolean requiresLowerCaseUrl() {
        return requiresLowerCaseUrl;
    }
}
