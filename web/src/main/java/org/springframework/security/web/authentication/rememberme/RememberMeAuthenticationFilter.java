/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.authentication.rememberme;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;


/**
 * Detects if there is no <code>Authentication</code> object in the <code>SecurityContext</code>, and populates it
 * with a remember-me authentication token if a {@link org.springframework.security.web.authentication.RememberMeServices}
 * implementation so requests.<p>Concrete <code>RememberMeServices</code> implementations will have their {@link
 * org.springframework.security.web.authentication.RememberMeServices#autoLogin(HttpServletRequest, HttpServletResponse)} method
 * called by this filter. The <code>Authentication</code> or <code>null</code> returned by that method will be placed
 * into the <code>SecurityContext</code>. The <code>AuthenticationManager</code> will be used, so that any concurrent
 * session management or other authentication-specific behaviour can be achieved. This is the same pattern as with
 * other authentication mechanisms, which call the <code>AuthenticationManager</code> as part of their contract.</p>
 *  <p>If authentication is successful, an {@link
 * org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent} will be published to the application
 * context. No events will be published if authentication was unsuccessful, because this would generally be recorded
 * via an <code>AuthenticationManager</code>-specific application event.</p>
 *
 * @author Ben Alex
 */
public class RememberMeAuthenticationFilter extends GenericFilterBean implements ApplicationEventPublisherAware {

    //~ Instance fields ================================================================================================

    private ApplicationEventPublisher eventPublisher;
    private AuthenticationManager authenticationManager;
    private RememberMeServices rememberMeServices;

    //~ Methods ========================================================================================================

    @Override
    public void afterPropertiesSet() {
        Assert.notNull(authenticationManager, "authenticationManager must be specified");
        Assert.notNull(rememberMeServices, "rememberMeServices must be specified");
    }

    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            Authentication rememberMeAuth = rememberMeServices.autoLogin(request, response);

            if (rememberMeAuth != null) {
                // Attempt authenticaton via AuthenticationManager
                try {
                    rememberMeAuth = authenticationManager.authenticate(rememberMeAuth);

                    // Store to SecurityContextHolder
                    SecurityContextHolder.getContext().setAuthentication(rememberMeAuth);

                    onSuccessfulAuthentication(request, response, rememberMeAuth);

                    if (logger.isDebugEnabled()) {
                        logger.debug("SecurityContextHolder populated with remember-me token: '"
                            + SecurityContextHolder.getContext().getAuthentication() + "'");
                    }

                    // Fire event
                    if (this.eventPublisher != null) {
                        eventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(
                                SecurityContextHolder.getContext().getAuthentication(), this.getClass()));
                    }
                } catch (AuthenticationException authenticationException) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("SecurityContextHolder not populated with remember-me token, as "
                                + "AuthenticationManager rejected Authentication returned by RememberMeServices: '"
                                + rememberMeAuth + "'; invalidating remember-me token", authenticationException);
                    }

                    rememberMeServices.loginFail(request, response);

                    onUnsuccessfulAuthentication(request, response, authenticationException);
                }
            }

            chain.doFilter(request, response);
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug("SecurityContextHolder not populated with remember-me token, as it already contained: '"
                    + SecurityContextHolder.getContext().getAuthentication() + "'");
            }

            chain.doFilter(request, response);
        }
    }

    /**
     * Called if a remember-me token is presented and successfully authenticated by the <tt>RememberMeServices</tt>
     * <tt>autoLogin</tt> method and the <tt>AuthenticationManager</tt>.
     */
    protected void onSuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
            Authentication authResult) {
    }

    /**
     * Called if the <tt>AuthenticationManager</tt> rejects the authentication object returned from the
     * <tt>RememberMeServices</tt> <tt>autoLogin</tt> method. This method will not be called when no remember-me
     * token is present in the request and <tt>autoLogin</tt> returns null.
     */
    protected void onUnsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException failed) {
    }

    public RememberMeServices getRememberMeServices() {
        return rememberMeServices;
    }

    public void setApplicationEventPublisher(ApplicationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    public void setRememberMeServices(RememberMeServices rememberMeServices) {
        this.rememberMeServices = rememberMeServices;
    }
}
