package org.springframework.security.web.util;

import javax.servlet.http.HttpServletRequest;

/**
 * Matches any supplied request.
 *
 * @author Luke Taylor
 * @since 3.1
 * @deprecated use org.springframework.security.web.util.matchers.AnyRequestMatcher.INSTANCE instead
 */
public final class AnyRequestMatcher implements RequestMatcher {
    private final RequestMatcher delegate = org.springframework.security.web.util.matchers.AnyRequestMatcher.INSTANCE;

    public boolean matches(HttpServletRequest request) {
        return delegate.matches(request);
    }

    @Override
    public boolean equals(Object obj) {
        return delegate.equals(obj);
    }

    @Override
    public int hashCode() {
        return delegate.hashCode();
    }
}
