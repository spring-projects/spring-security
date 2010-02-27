package org.springframework.security.web.context;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * @author Luke Taylor
 * @since 3.1
 */
public final class NullSecurityContextRepository implements SecurityContextRepository {

    public boolean containsContext(HttpServletRequest request) {
        return false;
    }

    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        return SecurityContextHolder.createEmptyContext();
    }

    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
    }

}
