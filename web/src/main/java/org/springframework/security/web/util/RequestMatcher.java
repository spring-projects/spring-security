package org.springframework.security.web.util;

import javax.servlet.http.HttpServletRequest;

/**
 * Simple strategy to match an <tt>HttpServletRequest</tt>.
 *
 * @author Luke Taylor
 * @since 3.0.2
 * @deprecated use {@link org.springframework.security.web.util.matcher.RequestMatcher}
 */
public interface RequestMatcher extends org.springframework.security.web.util.matcher.RequestMatcher {

    /**
     * Decides whether the rule implemented by the strategy matches the supplied request.
     *
     * @param request the request to check for a match
     * @return true if the request matches, false otherwise
     */
    boolean matches(HttpServletRequest request);

}
