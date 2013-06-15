package org.springframework.security.web.authentication.session;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * The default implementation of {@link SessionAuthenticationStrategy}.
 * <p>
 * Applies a session fixation protection scheme to a newly authenticated session. This scheme is configured using the
 * {@link #setSessionFixationProtectionScheme(SessionFixationProtectionScheme)} property and can take one of many forms.
 * It may make no changes to the session. It may invalidate the existing session, create a new session, and migrate
 * some or all of the session attributes to the new session. If configured using
 * {@link SessionFixationProtectionScheme#CHANGE_SESSION_ID} and in a Servlet 3.1 container, it will simply change
 * the session ID without invalidating and re-creating the session (the ideal solution).
 * <p>
 * For more information about how these different schemes work, see the documentation for
 * {@link SessionFixationProtectionScheme}.
 * <p>
 * <h3>Issues with {@link javax.servlet.http.HttpSessionBindingListener}</h3>
 * <p>
 * The migration of existing attributes to the newly-created session may cause problems if any of the objects
 * implement the {@code HttpSessionBindingListener} interface in a way which makes assumptions about the life-cycle of
 * the object. An example is the use of Spring session-scoped beans, where the initial removal of the bean from the
 * session will cause the {@code DisposableBean} interface to be invoked, in the assumption that the bean is no longer
 * required.
 * <p>
 * We recommend you use {@link SessionFixationProtectionScheme#CHANGE_SESSION_ID} when possible, as it avoids this
 * problem entirely. However, if you are not using Servlet 3.1 or newer and cannot use {@code CHANGE_SESSION_ID}, you
 * must take account of this issue when designing your application and should not store attributes which may not
 * function correctly when they are removed from and then placed back into the session. Alternatively, you can create a
 * custom {@link SessionAuthenticationStrategy} to deal with this issue, which will disable concurrent session control
 * and the built-in session fixation protection.
 * <p>
 * Due to this problem, in a Servlet 3.1 environment the default scheme is
 * {@link SessionFixationProtectionScheme#CHANGE_SESSION_ID}.
 *
 * @author Luke Taylor
 * @author Nicholas Williams
 * @since 3.2
 * @see SessionFixationProtectionScheme
 */
public class SessionFixationProtectionSchemeStrategy
        implements SessionAuthenticationStrategy, ApplicationEventPublisherAware {

    protected final Log logger = LogFactory.getLog(this.getClass());

    /**
     * Used for publishing events related to session fixation protection, such as {@link SessionFixationProtectionEvent}.
     */
    private ApplicationEventPublisher applicationEventPublisher = new NullEventPublisher();

    /**
     * Defines the scheme used to apply session fixation protection to a successful authentication.
     */
    private SessionFixationProtectionScheme scheme = SessionFixationProtectionScheme.getDefault();

    /**
     * If set to {@code true}, a session will always be created, even if one didn't exist at the start of the request.
     * Defaults to {@code false}.
     */
    private boolean alwaysCreateSession;

    /**
     * Called when a user is newly authenticated.
     * <p>
     * If a session already exists, and matches the session Id from the client, session fixation protection will be
     * applied according to the configured {@link #setSessionFixationProtectionScheme scheme}. If the client's requested
     * session Id is invalid, nothing will be done, since there is no need to change the session Id if it doesn't match
     * the current session.
     * <p>
     * If there is no session, no action is taken unless the {@code alwaysCreateSession} property is set, in which
     * case a session will be created if one doesn't already exist.
     */
    public void onAuthentication(Authentication authentication, HttpServletRequest request, HttpServletResponse response)
            throws SessionAuthenticationException {
        boolean hadSessionAlready = request.getSession(false) != null;
        if (!hadSessionAlready && !this.alwaysCreateSession) {
            // Session fixation isn't a problem if there's no session
            return;
        }

        // Create new session if necessary
        HttpSession session = request.getSession();
        if (hadSessionAlready && request.isRequestedSessionIdValid() &&
                this.scheme != SessionFixationProtectionScheme.NONE) {
            // We need to migrate to a new session
            String originalSessionId = session.getId();

            if (this.logger.isDebugEnabled()) {
                this.logger.debug("Applying session fixation protection to session [" + originalSessionId +
                        "] using scheme [" + this.scheme + "].");
            }

            this.scheme.applySessionFixationProtection(authentication, request);

            session = request.getSession();
            if (originalSessionId.equals(session.getId())) {
                this.logger.warn("Your servlet container did not change the session ID when session fixation protection " +
                        "was applied. You will not be adequately protected against session-fixation attacks");
            }

            this.onSessionChange(originalSessionId, session, authentication);
        }
    }

    /**
     * Called when the session has been changed and the old attributes have been migrated to the new session.
     * Only called if a session existed to start with. Allows subclasses to plug in additional behaviour.
     * * <p>
     * The default implementation of this method publishes a {@link SessionFixationProtectionEvent} to notify
     * the application that the session ID has changed. If you override this method and still wish these events to be
     * published, you should call {@code super.onSessionChange()} within your overriding method.
     *
     * @param originalSessionId The original session identifier.
     * @param newSession The newly created session.
     * @param auth The token for the newly authenticated principal.
     */
    protected void onSessionChange(String originalSessionId, HttpSession newSession, Authentication auth) {
        this.applicationEventPublisher.publishEvent(new SessionFixationProtectionEvent(
                auth, originalSessionId, newSession.getId()
        ));
    }

    /**
     * Sets the {@link ApplicationEventPublisher} to use for submitting
     * {@link SessionFixationProtectionEvent}. The default is to not submit the
     * {@link SessionFixationProtectionEvent}.
     *
     * @param applicationEventPublisher The {@link ApplicationEventPublisher}. Cannot be null.
     * @throws IllegalArgumentException if {@code applicationEventPublisher} is null.
     */
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        Assert.notNull(applicationEventPublisher, "applicationEventPublisher cannot be null");
        this.applicationEventPublisher = applicationEventPublisher;
    }

    /**
     * Configures the scheme used when applying session fixation protection to a successful authentication. If not set,
     * this defaults to {@link SessionFixationProtectionScheme#CHANGE_SESSION_ID} in a Servlet 3.1 or newer container,
     * {@link SessionFixationProtectionScheme#MIGRATE_SESSION} otherwise.
     *
     * @param scheme The session fixation protection scheme to employ. Cannot be null.
     * @throws IllegalArgumentException if {@code scheme} is null.
     */
    public void setSessionFixationProtectionScheme(SessionFixationProtectionScheme scheme) {
        this.scheme = scheme;
    }

    /**
     * If set to {@code true}, a session will always be created, even if one didn't exist at the start of the request.
     * Defaults to {@code false}.
     *
     * @param alwaysCreateSession Whether a session should always be created.
     */
    public void setAlwaysCreateSession(boolean alwaysCreateSession) {
        this.alwaysCreateSession = alwaysCreateSession;
    }

    private static final class NullEventPublisher implements ApplicationEventPublisher {
        public void publishEvent(ApplicationEvent event) { }
    }
}
