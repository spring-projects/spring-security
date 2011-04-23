package org.springframework.security.web.util;

import javax.servlet.http.HttpServletRequest;

/**
 * Matches any supplied request.
 *
 * @author Luke Taylor
 * @since 3.1
 */
public final class AnyRequestMatcher implements RequestMatcher {

    public boolean matches(HttpServletRequest request) {
        return true;
    }

    @Override
    public boolean equals(Object obj) {
        return obj instanceof AnyRequestMatcher;
    }

    @Override
    public int hashCode() {
        return 1;
    }
}
