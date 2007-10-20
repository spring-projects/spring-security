package org.springframework.security.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.regex.Pattern;

/**
 * @author luke
 * @version $Id$
 */
public class RegexUrlPathMatcher implements UrlMatcher {
    private static final Log logger = LogFactory.getLog(RegexUrlPathMatcher.class);

    private boolean convertUrlToLowercaseBeforeComparison = true;

    public Object compile(String path) {
        return Pattern.compile(path);
    }

    public void setConvertUrlToLowercaseBeforeComparison(boolean convertUrlToLowercaseBeforeComparison) {
        this.convertUrlToLowercaseBeforeComparison = convertUrlToLowercaseBeforeComparison;
    }

    public boolean pathMatchesUrl(Object compiledPath, String url) {
        Pattern pattern = (Pattern)compiledPath;

        if (convertUrlToLowercaseBeforeComparison) {
            url = url.toLowerCase();
            if (logger.isDebugEnabled()) {
                logger.debug("Converted URL to lowercase, from: '" + url + "'; to: '" + url + "'");
            }
        }

        return pattern.matcher(url).matches();
    }

    public String getUniversalMatchPattern() {
        return "/.*";
    }
}
