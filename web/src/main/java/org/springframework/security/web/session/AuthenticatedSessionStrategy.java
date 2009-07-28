package org.springframework.security.web.session;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;

/**
 * Allows pluggable support for Http session-related behaviour when an authentication occurs.
 * <p>
 * Typical use would be to make sure a session exists or to change the session Id to guard against session-fixation 
 * attacks.
 * 
 * @author Luke Taylor
 * @version $Id$
 * @since
 */
public interface AuthenticatedSessionStrategy {
    
    /**
     * Performs Http session-related functionality when a new authentication occurs.
     */
    void onAuthenticationSuccess(Authentication authentication, HttpServletRequest request, HttpServletResponse response);

}
