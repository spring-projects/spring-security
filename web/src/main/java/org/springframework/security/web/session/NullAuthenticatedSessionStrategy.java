package org.springframework.security.web.session;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;

/**
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public final class NullAuthenticatedSessionStrategy implements AuthenticatedSessionStrategy {

    public void onAuthentication(Authentication authentication, HttpServletRequest request,
            HttpServletResponse response) {
    }
}
