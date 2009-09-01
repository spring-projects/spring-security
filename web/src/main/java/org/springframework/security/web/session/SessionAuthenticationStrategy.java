package org.springframework.security.web.session;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;

/**
 * Allows pluggable support for HttpSession-related behaviour when an authentication occurs.
 * <p>
 * Typical use would be to make sure a session exists or to change the session Id to guard against session-fixation
 * attacks.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since
 */
public interface SessionAuthenticationStrategy {

    /**
     * Performs Http session-related functionality when a new authentication occurs.
     *
     * @throws SessionAuthenticationException if it is decided that the authentication is not allowed for the session.
     *          This will typically be because the user has too many sessions open at once.
     */
    void onAuthentication(Authentication authentication, HttpServletRequest request, HttpServletResponse response)
        throws SessionAuthenticationException;

}
