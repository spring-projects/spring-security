package org.springframework.security.web.authentication.preauth;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Base class for processing filters that handle pre-authenticated authentication requests, where it is assumed
 * that the principal has already been authenticated by an external system.
 * <p>
 * The purpose is then only to extract the necessary information on the principal from the incoming request, rather
 * than to authenticate them. External authentication systems may provide this information via request data such as
 * headers or cookies which the pre-authentication system can extract. It is assumed that the external system is
 * responsible for the accuracy of the data and preventing the submission of forged values.
 *
 * Subclasses must implement the {@code getPreAuthenticatedPrincipal()} and {@code getPreAuthenticatedCredentials()}
 * methods. Subclasses of this filter are typically used in combination with a
 * {@code PreAuthenticatedAuthenticationProvider}, which is used to load additional data for the user.
 * This provider will reject null credentials, so the {@link #getPreAuthenticatedCredentials} method should not return
 * null for a valid principal.
 * <p>
 * If the security context already contains an {@code Authentication} object (either from a invocation of the
 * filter or because of some other authentication mechanism), the filter will do nothing by default. You can force
 * it to check for a change in the principal by setting the {@link #setCheckForPrincipalChanges(boolean)
 * checkForPrincipalChanges} property.
 * <p>
 * By default, the filter chain will proceed when an authentication attempt fails in order to allow other
 * authentication mechanisms to process the request. To reject the credentials immediately, set the
 * <tt>continueFilterChainOnUnsuccessfulAuthentication</tt> flag to false. The exception raised by the
 * <tt>AuthenticationManager</tt> will the be re-thrown. Note that this will not affect cases where the principal
 * returned by {@link #getPreAuthenticatedPrincipal} is null, when the chain will still proceed as normal.
 *
 * @author Luke Taylor
 * @author Ruud Senden
 * @since 2.0
 */
public abstract class AbstractPreAuthenticatedProcessingFilter extends GenericFilterBean implements
        ApplicationEventPublisherAware {

    private ApplicationEventPublisher eventPublisher = null;
    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource
            = new WebAuthenticationDetailsSource();
    private AuthenticationManager authenticationManager = null;
    private boolean continueFilterChainOnUnsuccessfulAuthentication = true;
    private boolean checkForPrincipalChanges;
    private boolean invalidateSessionOnPrincipalChange = true;

    /**
     * Check whether all required properties have been set.
     */
    @Override
    public void afterPropertiesSet() {
        Assert.notNull(authenticationManager, "An AuthenticationManager must be set");
    }

    /**
     * Try to authenticate a pre-authenticated user with Spring Security if the user has not yet been authenticated.
     */
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (logger.isDebugEnabled()) {
            logger.debug("Checking secure context token: " + SecurityContextHolder.getContext().getAuthentication());
        }

        if (requiresAuthentication((HttpServletRequest) request)) {
            doAuthenticate((HttpServletRequest) request, (HttpServletResponse) response);
        }

        chain.doFilter(request, response);
    }

    /**
     * Do the actual authentication for a pre-authenticated user.
     */
    private void doAuthenticate(HttpServletRequest request, HttpServletResponse response) {
        Authentication authResult;

        Object principal = getPreAuthenticatedPrincipal(request);
        Object credentials = getPreAuthenticatedCredentials(request);

        if (principal == null) {
            if (logger.isDebugEnabled()) {
                logger.debug("No pre-authenticated principal found in request");
            }

            return;
        }

        if (logger.isDebugEnabled()) {
            logger.debug("preAuthenticatedPrincipal = " + principal + ", trying to authenticate");
        }

        try {
            PreAuthenticatedAuthenticationToken authRequest = new PreAuthenticatedAuthenticationToken(principal, credentials);
            authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
            authResult = authenticationManager.authenticate(authRequest);
            successfulAuthentication(request, response, authResult);
        } catch (AuthenticationException failed) {
            unsuccessfulAuthentication(request, response, failed);

            if (!continueFilterChainOnUnsuccessfulAuthentication) {
                throw failed;
            }
        }
    }

    private boolean requiresAuthentication(HttpServletRequest request) {
        Authentication currentUser = SecurityContextHolder.getContext().getAuthentication();

        if (currentUser == null) {
            return true;
        }

        Object principal = getPreAuthenticatedPrincipal(request);
        if (checkForPrincipalChanges &&
                !currentUser.getName().equals(principal)) {
            logger.debug("Pre-authenticated principal has changed to " + principal + " and will be reauthenticated");

            if (invalidateSessionOnPrincipalChange) {
                HttpSession session = request.getSession(false);

                if (session != null) {
                    logger.debug("Invalidating existing session");
                    session.invalidate();
                }
            }

            return true;
        }

        return false;
    }

    /**
     * Puts the <code>Authentication</code> instance returned by the
     * authentication manager into the secure context.
     */
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, Authentication authResult) {
        if (logger.isDebugEnabled()) {
            logger.debug("Authentication success: " + authResult);
        }
        SecurityContextHolder.getContext().setAuthentication(authResult);
        // Fire event
        if (this.eventPublisher != null) {
            eventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(authResult, this.getClass()));
        }
    }

    /**
     * Ensures the authentication object in the secure context is set to null when authentication fails.
     * <p>
     * Caches the failure exception as a request attribute
     */
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
        SecurityContextHolder.clearContext();

        if (logger.isDebugEnabled()) {
            logger.debug("Cleared security context due to exception", failed);
        }
        request.setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, failed);
    }

    /**
     * @param anApplicationEventPublisher
     *            The ApplicationEventPublisher to use
     */
    public void setApplicationEventPublisher(ApplicationEventPublisher anApplicationEventPublisher) {
        this.eventPublisher = anApplicationEventPublisher;
    }

    /**
     * @param authenticationDetailsSource
     *            The AuthenticationDetailsSource to use
     */
    public void setAuthenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest,?> authenticationDetailsSource) {
        Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource required");
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    protected AuthenticationDetailsSource<HttpServletRequest, ?> getAuthenticationDetailsSource() {
        return authenticationDetailsSource;
    }

    /**
     * @param authenticationManager
     *            The AuthenticationManager to use
     */
    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    /**
     * If set to {@code true}, any {@code AuthenticationException} raised by the {@code AuthenticationManager} will be
     * swallowed, and the request will be allowed to proceed, potentially using alternative authentication mechanisms.
     * If {@code false} (the default), authentication failure will result in an immediate exception.
     *
     * @param shouldContinue set to {@code true} to allow the request to proceed after a failed authentication.
     */
    public void setContinueFilterChainOnUnsuccessfulAuthentication(boolean shouldContinue) {
        continueFilterChainOnUnsuccessfulAuthentication = shouldContinue;
    }

    /**
     * If set, the pre-authenticated principal will be checked on each request and compared
     * against the name of the current <tt>Authentication</tt> object. If a change is detected,
     * the user will be reauthenticated.
     *
     * @param checkForPrincipalChanges
     */
    public void setCheckForPrincipalChanges(boolean checkForPrincipalChanges) {
        this.checkForPrincipalChanges = checkForPrincipalChanges;
    }

    /**
     * If <tt>checkForPrincipalChanges</tt> is set, and a change of principal is detected, determines whether
     * any existing session should be invalidated before proceeding to authenticate the new principal.
     *
     * @param invalidateSessionOnPrincipalChange <tt>false</tt> to retain the existing session. Defaults to <tt>true</tt>.
     */
    public void setInvalidateSessionOnPrincipalChange(boolean invalidateSessionOnPrincipalChange) {
        this.invalidateSessionOnPrincipalChange = invalidateSessionOnPrincipalChange;
    }

    /**
     * Override to extract the principal information from the current request
     */
    protected abstract Object getPreAuthenticatedPrincipal(HttpServletRequest request);

    /**
     * Override to extract the credentials (if applicable) from the current request. Should not return null for a valid
     * principal, though some implementations may return a dummy value.
     */
    protected abstract Object getPreAuthenticatedCredentials(HttpServletRequest request);
}
