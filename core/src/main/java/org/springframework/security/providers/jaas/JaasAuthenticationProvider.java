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

package org.springframework.security.providers.jaas;

import org.springframework.security.SpringSecurityException;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.GrantedAuthority;

import org.springframework.security.context.HttpSessionContextIntegrationFilter;
import org.springframework.security.context.SecurityContext;

import org.springframework.security.providers.AuthenticationProvider;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.providers.jaas.event.JaasAuthenticationFailedEvent;
import org.springframework.security.providers.jaas.event.JaasAuthenticationSuccessEvent;

import org.springframework.security.ui.session.HttpSessionDestroyedEvent;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.context.*;

import org.springframework.core.io.Resource;

import org.springframework.util.Assert;

import java.io.IOException;

import java.security.Principal;
import java.security.Security;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;


/**
 * An {@link AuthenticationProvider} implementation that retrieves user details from a JAAS login configuration.
 *
 * <p>This <code>AuthenticationProvider</code> is capable of validating {@link
 * org.springframework.security.providers.UsernamePasswordAuthenticationToken} requests contain the correct username and
 * password.</p>
 * <p>This implementation is backed by a <a
 * href="http://java.sun.com/j2se/1.4.2/docs/guide/security/jaas/JAASRefGuide.html">JAAS</a> configuration. The
 * loginConfig property must be set to a given JAAS configuration file. This setter accepts a Spring {@link
 * org.springframework.core.io.Resource} instance. It should point to a JAAS configuration file containing an index
 * matching the {@link #setLoginContextName(java.lang.String) loginContextName} property.
 * </p>
 * <p>
 * For example: If this JaasAuthenticationProvider were configured in a Spring WebApplicationContext the xml to
 * set the loginConfiguration could be as follows...
 * <pre>
 * &lt;property name="loginConfig"&gt;
 *   &lt;value&gt;/WEB-INF/login.conf&lt;/value&gt;
 * &lt;/property&gt;
 * </pre>
 * </p>
 * <p>
 * The loginContextName should coincide with a given index in the loginConfig specifed. The loginConfig file
 * used in the JUnit tests appears as the following...
 * <pre> JAASTest {
 *   org.springframework.security.providers.jaas.TestLoginModule required;
 * };
 * </pre>
 * Using the example login configuration above, the loginContextName property would be set as <i>JAASTest</i>...
 * <pre>
 *  &lt;property name="loginContextName"&gt; &lt;value&gt;JAASTest&lt;/value&gt; &lt;/property&gt;
 * </pre>
 * </p>
 *  <p>When using JAAS login modules as the authentication source, sometimes the
 * <a href="http://java.sun.com/j2se/1.4.2/docs/api/javax/security/auth/login/LoginContext.html">LoginContext</a> will
 * require <i>CallbackHandler</i>s. The JaasAuthenticationProvider uses an internal
 * <a href="http://java.sun.com/j2se/1.4.2/docs/api/javax/security/auth/callback/CallbackHandler.html">CallbackHandler
 * </a> to wrap the {@link JaasAuthenticationCallbackHandler}s configured in the ApplicationContext.
 * When the LoginContext calls the internal CallbackHandler, control is passed to each
 * {@link JaasAuthenticationCallbackHandler} for each Callback passed.
 * </p>
 * <p>{@link JaasAuthenticationCallbackHandler}s are passed to the JaasAuthenticationProvider through the {@link
 * #setCallbackHandlers(org.springframework.security.providers.jaas.JaasAuthenticationCallbackHandler[]) callbackHandlers}
 * property.
 * <pre>
 * &lt;property name="callbackHandlers"&gt;
 *   &lt;list&gt;
 *     &lt;bean class="org.springframework.security.providers.jaas.TestCallbackHandler"/&gt;
 *     &lt;bean class="{@link JaasNameCallbackHandler org.springframework.security.providers.jaas.JaasNameCallbackHandler}"/&gt;
 *     &lt;bean class="{@link JaasPasswordCallbackHandler org.springframework.security.providers.jaas.JaasPasswordCallbackHandler}"/&gt;
 *  &lt;/list&gt;
 * &lt;/property&gt;
 * </pre>
 * </p>
 * <p>
 * After calling LoginContext.login(), the JaasAuthenticationProvider will retrieve the returned Principals
 * from the Subject (LoginContext.getSubject().getPrincipals). Each returned principal is then passed to the
 * configured {@link AuthorityGranter}s. An AuthorityGranter is a mapping between a returned Principal, and a role
 * name. If an AuthorityGranter wishes to grant an Authorization a role, it returns that role name from it's {@link
 * AuthorityGranter#grant(java.security.Principal)} method. The returned role will be applied to the Authorization
 * object as a {@link GrantedAuthority}.</p>
 * <p>AuthorityGranters are configured in spring xml as follows...
 * <pre>
 * &lt;property name="authorityGranters"&gt;
 *   &lt;list&gt;
 *     &lt;bean class="org.springframework.security.providers.jaas.TestAuthorityGranter"/&gt;
 *   &lt;/list&gt;
 *  &lt;/property&gt;
 * </pre>
 * A configuration note: The JaasAuthenticationProvider uses the security properites
 * &quote;login.config.url.X&quote; to configure jaas. If you would like to customize the way Jaas gets configured,
 * create a subclass of this and override the {@link #configureJaas(Resource)} method.
 * </p>
 *
 * @author Ray Krueger
 * @version $Id$
 */
public class JaasAuthenticationProvider implements AuthenticationProvider, ApplicationEventPublisherAware,
        InitializingBean, ApplicationListener {
    //~ Static fields/initializers =====================================================================================

    protected static final Log log = LogFactory.getLog(JaasAuthenticationProvider.class);

    //~ Instance fields ================================================================================================

    private LoginExceptionResolver loginExceptionResolver = new DefaultLoginExceptionResolver();
    private Resource loginConfig;
    private String loginContextName = "SPRINGSECURITY";
    private AuthorityGranter[] authorityGranters;
    private JaasAuthenticationCallbackHandler[] callbackHandlers;
    private ApplicationEventPublisher applicationEventPublisher;

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(loginConfig, "loginConfig must be set on " + getClass());
        Assert.hasLength(loginContextName, "loginContextName must be set on " + getClass());

        configureJaas(loginConfig);

        Assert.notNull(Configuration.getConfiguration(),
              "As per http://java.sun.com/j2se/1.5.0/docs/api/javax/security/auth/login/Configuration.html "
            + "\"If a Configuration object was set via the Configuration.setConfiguration method, then that object is "
            + "returned. Otherwise, a default Configuration object is returned\". Your JRE returned null to "
            + "Configuration.getConfiguration().");
    }

    /**
     * Attempts to login the user given the Authentication objects principal and credential
     *
     * @param auth The Authentication object to be authenticated.
     *
     * @return The authenticated Authentication object, with it's grantedAuthorities set.
     *
     * @throws AuthenticationException This implementation does not handle 'locked' or 'disabled' accounts. This method
     *         only throws a AuthenticationServiceException, with the message of the LoginException that will be
     *         thrown, should the loginContext.login() method fail.
     */
    public Authentication authenticate(Authentication auth)
        throws AuthenticationException {
        if (auth instanceof UsernamePasswordAuthenticationToken) {
            UsernamePasswordAuthenticationToken request = (UsernamePasswordAuthenticationToken) auth;

            try {
                //Create the LoginContext object, and pass our InternallCallbackHandler
                LoginContext loginContext = new LoginContext(loginContextName, new InternalCallbackHandler(auth));

                //Attempt to login the user, the LoginContext will call our InternalCallbackHandler at this point.
                loginContext.login();

                //create a set to hold the authorities, and add any that have already been applied.
                Set<GrantedAuthority> authorities = new HashSet();

                if (request.getAuthorities() != null) {
                    authorities.addAll(request.getAuthorities());
                }

                //get the subject principals and pass them to each of the AuthorityGranters
                Set principals = loginContext.getSubject().getPrincipals();

                for (Iterator iterator = principals.iterator(); iterator.hasNext();) {
                    Principal principal = (Principal) iterator.next();

                    for (int i = 0; i < authorityGranters.length; i++) {
                        AuthorityGranter granter = authorityGranters[i];
                        Set roles = granter.grant(principal);

                        //If the granter doesn't wish to grant any authorities, it should return null.
                        if ((roles != null) && !roles.isEmpty()) {
                            for (Iterator roleIterator = roles.iterator(); roleIterator.hasNext();) {
                                String role = roleIterator.next().toString();
                                authorities.add(new JaasGrantedAuthority(role, principal));
                            }
                        }
                    }
                }

                //Convert the authorities set back to an array and apply it to the token.
                JaasAuthenticationToken result = new JaasAuthenticationToken(request.getPrincipal(),
                        request.getCredentials(),
                        (GrantedAuthority[]) authorities.toArray(new GrantedAuthority[0]), loginContext);

                //Publish the success event
                publishSuccessEvent(result);

                //we're done, return the token.
                return result;
            } catch (LoginException loginException) {
                SpringSecurityException ase = loginExceptionResolver.resolveException(loginException);

                publishFailureEvent(request, ase);
                throw ase;
            }
        }

        return null;
    }

    /**
     * Hook method for configuring Jaas
     *
     * @param loginConfig URL to Jaas login configuration
     *
     * @throws IOException if there is a problem reading the config resource.
     */
    protected void configureJaas(Resource loginConfig) throws IOException {
        configureJaasUsingLoop();

        // Overcome issue in SEC-760
        Configuration.getConfiguration().refresh();
    }

    /**
     * Loops through the login.config.url.1,login.config.url.2 properties looking for the login configuration.
     * If it is not set, it will be set to the last available login.config.url.X property.
     *
     */
    private void configureJaasUsingLoop() throws IOException {
        String loginConfigUrl = loginConfig.getURL().toString();
        boolean alreadySet = false;

        int n = 1;
        String prefix = "login.config.url.";
        String existing = null;

        while ((existing = Security.getProperty(prefix + n)) != null) {
            alreadySet = existing.equals(loginConfigUrl);

            if (alreadySet) {
                break;
            }

            n++;
        }

        if (!alreadySet) {
            String key = prefix + n;
            log.debug("Setting security property [" + key + "] to: " + loginConfigUrl);
            Security.setProperty(key, loginConfigUrl);
        }
    }

    /**
     * Returns the AuthorityGrannter array that was passed to the {@link
     * #setAuthorityGranters(AuthorityGranter[])} method, or null if it none were ever set.
     *
     * @return The AuthorityGranter array, or null
     *
     * @see #setAuthorityGranters(AuthorityGranter[])
     */
    public AuthorityGranter[] getAuthorityGranters() {
        return authorityGranters;
    }

    /**
     * Returns the current JaasAuthenticationCallbackHandler array, or null if none are set.
     *
     * @return the JAASAuthenticationCallbackHandlers.
     *
     * @see #setCallbackHandlers(JaasAuthenticationCallbackHandler[])
     */
    public JaasAuthenticationCallbackHandler[] getCallbackHandlers() {
        return callbackHandlers;
    }

    public Resource getLoginConfig() {
        return loginConfig;
    }

    public String getLoginContextName() {
        return loginContextName;
    }

    public LoginExceptionResolver getLoginExceptionResolver() {
        return loginExceptionResolver;
    }

    /**
     * Handles the logout by getting the SecurityContext for the session that was destroyed. <b>MUST NOT use
     * SecurityContextHolder we are logging out a session that is not related to the current user.</b>
     *
     * @param event
     */
    protected void handleLogout(HttpSessionDestroyedEvent event) {
        SecurityContext context = (SecurityContext)
                event.getSession().getAttribute(HttpSessionContextIntegrationFilter.SPRING_SECURITY_CONTEXT_KEY);

        if (context == null) {
            log.debug("The destroyed session has no SecurityContext");

            return;
        }

        Authentication auth = context.getAuthentication();

        if ((auth != null) && (auth instanceof JaasAuthenticationToken)) {
            JaasAuthenticationToken token = (JaasAuthenticationToken) auth;

            try {
                LoginContext loginContext = token.getLoginContext();

                if (loginContext != null) {
                    log.debug("Logging principal: [" + token.getPrincipal() + "] out of LoginContext");
                    loginContext.logout();
                } else {
                    log.debug("Cannot logout principal: [" + token.getPrincipal() + "] from LoginContext. "
                        + "The LoginContext is unavailable");
                }
            } catch (LoginException e) {
                log.warn("Error error logging out of LoginContext", e);
            }
        }
    }

    public void onApplicationEvent(ApplicationEvent applicationEvent) {
        if (applicationEvent instanceof HttpSessionDestroyedEvent) {
            HttpSessionDestroyedEvent event = (HttpSessionDestroyedEvent) applicationEvent;
            handleLogout(event);
        }
    }

    /**
     * Publishes the {@link JaasAuthenticationFailedEvent}. Can be overridden by subclasses for different
     * functionality
     *
     * @param token The {@link UsernamePasswordAuthenticationToken} being processed
     * @param ase The {@link SpringSecurityException} that caused the failure
     */
    protected void publishFailureEvent(UsernamePasswordAuthenticationToken token, SpringSecurityException ase) {
        applicationEventPublisher.publishEvent(new JaasAuthenticationFailedEvent(token, ase));
    }

    /**
     * Publishes the {@link JaasAuthenticationSuccessEvent}. Can be overridden by subclasses for different
     * functionality.
     *
     * @param token The {@link UsernamePasswordAuthenticationToken} being processed
     */
    protected void publishSuccessEvent(UsernamePasswordAuthenticationToken token) {
        if (applicationEventPublisher != null) {
            applicationEventPublisher.publishEvent(new JaasAuthenticationSuccessEvent(token));
        }
    }

    /**
     * Set the AuthorityGranters that should be consulted for role names to be granted to the Authentication.
     *
     * @param authorityGranters AuthorityGranter array
     *
     * @see JaasAuthenticationProvider
     */
    public void setAuthorityGranters(AuthorityGranter[] authorityGranters) {
        this.authorityGranters = authorityGranters;
    }

    /**
     * Set the JAASAuthentcationCallbackHandler array to handle callback objects generated by the
     * LoginContext.login method.
     *
     * @param callbackHandlers Array of JAASAuthenticationCallbackHandlers
     */
    public void setCallbackHandlers(JaasAuthenticationCallbackHandler[] callbackHandlers) {
        this.callbackHandlers = callbackHandlers;
    }

    /**
     * Set the JAAS login configuration file.
     *
     * @param loginConfig <a
     *        href="http://www.springframework.org/docs/api/org/springframework/core/io/Resource.html">Spring
     *        Resource</a>
     *
     * @see <a href="http://java.sun.com/j2se/1.4.2/docs/guide/security/jaas/JAASRefGuide.html">JAAS Reference</a>
     */
    public void setLoginConfig(Resource loginConfig) {
        this.loginConfig = loginConfig;
    }

    /**
     * Set the loginContextName, this name is used as the index to the configuration specified in the
     * loginConfig property.
     *
     * @param loginContextName
     */
    public void setLoginContextName(String loginContextName) {
        this.loginContextName = loginContextName;
    }

    public void setLoginExceptionResolver(LoginExceptionResolver loginExceptionResolver) {
        this.loginExceptionResolver = loginExceptionResolver;
    }

    public boolean supports(Class<? extends Object> aClass) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(aClass);
    }

    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.applicationEventPublisher = applicationEventPublisher;
    }

    protected ApplicationEventPublisher getApplicationEventPublisher() {
        return applicationEventPublisher;
    }

    //~ Inner Classes ==================================================================================================

    /**
     * Wrapper class for JAASAuthenticationCallbackHandlers
     */
    private class InternalCallbackHandler implements CallbackHandler {
        private Authentication authentication;

        public InternalCallbackHandler(Authentication authentication) {
            this.authentication = authentication;
        }

        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (int i = 0; i < callbackHandlers.length; i++) {
                JaasAuthenticationCallbackHandler handler = callbackHandlers[i];

                for (int j = 0; j < callbacks.length; j++) {
                    Callback callback = callbacks[j];

                    handler.handle(callback, authentication);
                }
            }
        }
    }
}
