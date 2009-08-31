package org.springframework.security.web.session;

import org.springframework.security.core.AuthenticationException;

/**
 * Thrown by an <tt>SessionAuthenticationStrategy</tt> to indicate that an authentication object is not valid for
 * the current session, typically because the same user has exceeded the number of sessions they are allowed to have
 * concurrently.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public class SessionAuthenticationException extends AuthenticationException {

    public SessionAuthenticationException(String msg) {
        super(msg);
    }

}
