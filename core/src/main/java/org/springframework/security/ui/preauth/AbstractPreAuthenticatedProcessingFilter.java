package org.springframework.security.ui.preauth;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.providers.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.AuthenticationManager;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.event.authentication.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.ui.AuthenticationDetailsSource;
import org.springframework.security.ui.AuthenticationDetailsSourceImpl;
import org.springframework.security.ui.AbstractProcessingFilter;
import org.springframework.security.ui.SpringSecurityFilter;
import org.springframework.security.context.SecurityContextHolder;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.util.Assert;

/**
 * Base class for processing filters that handle pre-authenticated authentication requests. Subclasses must implement
 * the getPreAuthenticatedPrincipal() and getPreAuthenticatedCredentials() methods.
 *
 * @author Luke Taylor
 * @author Ruud Senden
 * @since 2.0
 */
public abstract class AbstractPreAuthenticatedProcessingFilter extends SpringSecurityFilter implements
        InitializingBean, ApplicationEventPublisherAware {

    protected final Log logger = LogFactory.getLog(getClass());

    private ApplicationEventPublisher eventPublisher = null;

    private AuthenticationDetailsSource authenticationDetailsSource = new AuthenticationDetailsSourceImpl();

    private AuthenticationManager authenticationManager = null;

    /**
     * Check whether all required properties have been set.
     */
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(authenticationManager, "An AuthenticationManager must be set");
    }

    /**
     * Try to authenticate a pre-authenticated user with Spring Security if the user has not yet been authenticated.
     */
    public void doFilterHttp(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        if (logger.isDebugEnabled()) {
            logger.debug("Checking secure context token: " + SecurityContextHolder.getContext().getAuthentication());
        }

        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            doAuthenticate(request, response);
        }
        filterChain.doFilter(request, response);
    }

    /**
     * Do the actual authentication for a pre-authenticated user.
     */
    private void doAuthenticate(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        Authentication authResult = null;

        Object principal = getPreAuthenticatedPrincipal(httpRequest);
        Object credentials = getPreAuthenticatedCredentials(httpRequest);

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
            authRequest.setDetails(authenticationDetailsSource.buildDetails(httpRequest));
            authResult = authenticationManager.authenticate(authRequest);
            successfulAuthentication(httpRequest, httpResponse, authResult);
        } catch (AuthenticationException failed) {
            unsuccessfulAuthentication(httpRequest, httpResponse, failed);
        }
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
     * Ensures the authentication object in the secure context is set to null
     * when authentication fails.
     */
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
        SecurityContextHolder.clearContext();

        if (logger.isDebugEnabled()) {
            logger.debug("Cleared security context due to exception", failed);
        }
        request.getSession().setAttribute(AbstractProcessingFilter.SPRING_SECURITY_LAST_EXCEPTION_KEY, failed);
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
    public void setAuthenticationDetailsSource(AuthenticationDetailsSource authenticationDetailsSource) {
        Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource required");
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    /**
     * @param authenticationManager
     *            The AuthenticationManager to use
     */
    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    protected abstract Object getPreAuthenticatedPrincipal(HttpServletRequest httpRequest);

    protected abstract Object getPreAuthenticatedCredentials(HttpServletRequest httpRequest);
}
