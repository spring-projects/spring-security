package org.springframework.security.util;

/**
 * Strategy for deciding whether configured path matches a submitted candidate URL.
 *
 * @author luke
 * @version $Id$
 * @since 2.0
 */
public interface UrlMatcher {

    Object compile(String urlPattern);

    boolean pathMatchesUrl(Object compiledUrlPattern, String url);

    /** Returns the path which matches every URL */
    String getUniversalMatchPattern();
}
