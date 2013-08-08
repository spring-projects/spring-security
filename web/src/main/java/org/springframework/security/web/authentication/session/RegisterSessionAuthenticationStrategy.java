package org.springframework.security.web.authentication.session;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.util.Assert;

/**
 * Strategy used to register a user with the {@link SessionRegistry} after
 * successful {@link Authentication}.
 *
 * <p>
 * {@link RegisterSessionAuthenticationStrategy} is typically used in
 * combination with {@link CompositeSessionAuthenticationStrategy} and
 * {@link ConcurrentSessionControlAuthenticationStrategy}, but can be used on
 * its own if tracking of sessions is desired but no need to control
 * concurrency.</P
 *
 * <p>
 * NOTE: When using a {@link SessionRegistry} it is important that all sessions
 * (including timed out sessions) are removed. This is typically done by adding
 * {@link HttpSessionEventPublisher}.</p>
 *
 * @see CompositeSessionAuthenticationStrategy
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @since 3.2
 */
public class RegisterSessionAuthenticationStrategy implements SessionAuthenticationStrategy {
    private final SessionRegistry sessionRegistry;

    /**
     * @param sessionRegistry the session registry which should be updated when the authenticated session is changed.
     */
    public RegisterSessionAuthenticationStrategy(SessionRegistry sessionRegistry) {
        Assert.notNull(sessionRegistry, "The sessionRegistry cannot be null");
        this.sessionRegistry = sessionRegistry;
    }

    /**
     * In addition to the steps from the superclass, the sessionRegistry will be updated with the new session information.
     */
    public void onAuthentication(Authentication authentication, HttpServletRequest request,
            HttpServletResponse response) {
        sessionRegistry.registerNewSession(request.getSession().getId(), authentication.getPrincipal());
    }
}
