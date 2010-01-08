package org.springframework.security.web.authentication.session;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;

/**
 *
 * @author Luke Taylor
 * @since 3.0
 */
public final class NullAuthenticatedSessionStrategy implements SessionAuthenticationStrategy {

    public void onAuthentication(Authentication authentication, HttpServletRequest request,
            HttpServletResponse response) {
    }
}
