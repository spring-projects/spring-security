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

package org.springframework.security.providers;

import org.springframework.security.AbstractAuthenticationManager;
import org.springframework.security.AccountExpiredException;
import org.springframework.security.SpringSecurityMessageSource;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.AuthenticationServiceException;
import org.springframework.security.BadCredentialsException;
import org.springframework.security.CredentialsExpiredException;
import org.springframework.security.DisabledException;
import org.springframework.security.LockedException;
import org.springframework.security.AccountStatusException;
import org.springframework.security.concurrent.ConcurrentLoginException;
import org.springframework.security.concurrent.ConcurrentSessionController;
import org.springframework.security.concurrent.NullConcurrentSessionController;
import org.springframework.security.event.authentication.AbstractAuthenticationEvent;
import org.springframework.security.event.authentication.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.event.authentication.AuthenticationFailureConcurrentLoginEvent;
import org.springframework.security.event.authentication.AuthenticationFailureCredentialsExpiredEvent;
import org.springframework.security.event.authentication.AuthenticationFailureDisabledEvent;
import org.springframework.security.event.authentication.AuthenticationFailureExpiredEvent;
import org.springframework.security.event.authentication.AuthenticationFailureLockedEvent;
import org.springframework.security.event.authentication.AuthenticationFailureProviderNotFoundEvent;
import org.springframework.security.event.authentication.AuthenticationFailureProxyUntrustedEvent;
import org.springframework.security.event.authentication.AuthenticationFailureServiceExceptionEvent;
import org.springframework.security.event.authentication.AuthenticationSuccessEvent;
import org.springframework.security.userdetails.UsernameNotFoundException;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.util.Assert;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

import java.util.Iterator;
import java.util.List;
import java.util.Properties;


/**
 * Iterates an {@link Authentication} request through a list of {@link AuthenticationProvider}s.
 *
 * Can optionally be configured with a {@link ConcurrentSessionController} to limit the number of sessions a user can
 * have.
 * <p>
 * <tt>AuthenticationProvider</tt>s are usually tried in order until one provides a non-null response.
 * A non-null response indicates the provider had authority to decide on the authentication request and no further
 * providers are tried.
 * If a subsequent provider successfully authenticates the request, the earlier authentication exception is disregarded
 * and the successful authentication will be used. If no subsequent provider provides a non-null response, or a new
 * <code>AuthenticationException</code>, the last <code>AuthenticationException</code> received will be used.
 * If no provider returns a non-null response, or indicates it can even process an <code>Authentication</code>,
 * the <code>ProviderManager</code> will throw a <code>ProviderNotFoundException</code>.
 * <p>
 * The exception to this process is when a provider throws an {@link AccountStatusException} or if the configured
 * concurrent session controller throws a {@link ConcurrentLoginException}. In both these cases, no further providers
 * in the list will be queried.
 *
 * <p>
 * If a valid <code>Authentication</code> is returned by an <code>AuthenticationProvider</code>, the
 * <code>ProviderManager</code> will publish an
 * {@link org.springframework.security.event.authentication.AuthenticationSuccessEvent}. If an
 * <code>AuthenticationException</code> is detected, the final <code>AuthenticationException</code> thrown will be
 * used to publish an appropriate failure event. By default <code>ProviderManager</code> maps common exceptions to
 * events, but this can be fine-tuned by providing a new <code>exceptionMappings</code><code>java.util.Properties</code>
 * object. In the properties object, each of the keys represent the fully qualified classname of the exception, and
 * each of the values represent the name of an event class which subclasses
 * {@link org.springframework.security.event.authentication.AbstractAuthenticationFailureEvent}
 * and provides its constructor.
 *
 *
 * @author Ben Alex
 * @version $Id$
 * @see ConcurrentSessionController
 */
public class ProviderManager extends AbstractAuthenticationManager implements InitializingBean, MessageSourceAware,
        ApplicationEventPublisherAware  {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(ProviderManager.class);
    private static final Properties DEFAULT_EXCEPTION_MAPPINGS = new Properties();

    //~ Instance fields ================================================================================================

    private ApplicationEventPublisher applicationEventPublisher;
    private ConcurrentSessionController sessionController = new NullConcurrentSessionController();
    private List providers;
    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
    private Properties exceptionMappings = new Properties();
    private Properties additionalExceptionMappings = new Properties();

    static {
        DEFAULT_EXCEPTION_MAPPINGS.put(AccountExpiredException.class.getName(),
                AuthenticationFailureExpiredEvent.class.getName());
        DEFAULT_EXCEPTION_MAPPINGS.put(AuthenticationServiceException.class.getName(),
                AuthenticationFailureServiceExceptionEvent.class.getName());
        DEFAULT_EXCEPTION_MAPPINGS.put(LockedException.class.getName(),
                AuthenticationFailureLockedEvent.class.getName());
        DEFAULT_EXCEPTION_MAPPINGS.put(CredentialsExpiredException.class.getName(),
                AuthenticationFailureCredentialsExpiredEvent.class.getName());
        DEFAULT_EXCEPTION_MAPPINGS.put(DisabledException.class.getName(),
                AuthenticationFailureDisabledEvent.class.getName());
        DEFAULT_EXCEPTION_MAPPINGS.put(BadCredentialsException.class.getName(),
                AuthenticationFailureBadCredentialsEvent.class.getName());
        DEFAULT_EXCEPTION_MAPPINGS.put(UsernameNotFoundException.class.getName(),
                AuthenticationFailureBadCredentialsEvent.class.getName());
        DEFAULT_EXCEPTION_MAPPINGS.put(ConcurrentLoginException.class.getName(),
                AuthenticationFailureConcurrentLoginEvent.class.getName());
        DEFAULT_EXCEPTION_MAPPINGS.put(ProviderNotFoundException.class.getName(),
                AuthenticationFailureProviderNotFoundEvent.class.getName());
        DEFAULT_EXCEPTION_MAPPINGS.put("org.springframework.security.providers.cas.ProxyUntrustedException",
                AuthenticationFailureProxyUntrustedEvent.class.getName());
    }

    public ProviderManager() {
        exceptionMappings.putAll(DEFAULT_EXCEPTION_MAPPINGS);
    }

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.messages, "A message source must be set");
        exceptionMappings.putAll(additionalExceptionMappings);
    }

    /**
     * Attempts to authenticate the passed {@link Authentication} object.
     * <p>
     * The list of {@link AuthenticationProvider}s will be successively tried until an
     * <code>AuthenticationProvider</code> indicates it is  capable of authenticating the type of
     * <code>Authentication</code> object passed. Authentication will then be attempted with that
     * <code>AuthenticationProvider</code>.
     * <p>
     * If more than one <code>AuthenticationProvider</code> supports the passed <code>Authentication</code>
     * object, only the first <code>AuthenticationProvider</code> tried will determine the result. No subsequent
     * <code>AuthenticationProvider</code>s will be tried.
     *
     * @param authentication the authentication request object.
     *
     * @return a fully authenticated object including credentials.
     *
     * @throws AuthenticationException if authentication fails.
     */
    public Authentication doAuthentication(Authentication authentication) throws AuthenticationException {
        Iterator iter = getProviders().iterator();

        Class toTest = authentication.getClass();

        AuthenticationException lastException = null;

        while (iter.hasNext()) {
            AuthenticationProvider provider = (AuthenticationProvider) iter.next();

            if (!provider.supports(toTest)) {
                continue;
            }

            logger.debug("Authentication attempt using " + provider.getClass().getName());

            Authentication result;

            try {
                result = provider.authenticate(authentication);

                if (result != null) {
                    copyDetails(authentication, result);
                    sessionController.checkAuthenticationAllowed(result);
                }
            } catch (AuthenticationException ae) {
                lastException = ae;
                result = null;
            }

            // SEC-546: Avoid polling additional providers if auth failure is due to invalid account status or
            // disallowed concurrent login.
            if (lastException instanceof AccountStatusException || lastException instanceof ConcurrentLoginException) {
                break;
            }

            if (result != null) {
                sessionController.registerSuccessfulAuthentication(result);
                publishEvent(new AuthenticationSuccessEvent(result));

                return result;
            }
        }

        if (lastException == null) {
            lastException = new ProviderNotFoundException(messages.getMessage("ProviderManager.providerNotFound",
                        new Object[] {toTest.getName()}, "No AuthenticationProvider found for {0}"));
        }

        publishAuthenticationFailure(lastException, authentication);

        throw lastException;
    }

    private void publishAuthenticationFailure(AuthenticationException exception, Authentication authentication) {
        String className = exceptionMappings.getProperty(exception.getClass().getName());
        AbstractAuthenticationEvent event = null;

        if (className != null) {
            try {
                Class clazz = getClass().getClassLoader().loadClass(className);
                Constructor constructor = clazz.getConstructor(new Class[] {
                            Authentication.class, AuthenticationException.class
                        });
                Object obj = constructor.newInstance(new Object[] {authentication, exception});
                Assert.isInstanceOf(AbstractAuthenticationEvent.class, obj, "Must be an AbstractAuthenticationEvent");
                event = (AbstractAuthenticationEvent) obj;
            } catch (ClassNotFoundException ignored) {}
            catch (NoSuchMethodException ignored) {}
            catch (IllegalAccessException ignored) {}
            catch (InstantiationException ignored) {}
            catch (InvocationTargetException ignored) {}
        }

        if (event != null) {
            publishEvent(event);
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug("No event was found for the exception " + exception.getClass().getName());
            }
        }

    }

    /**
     * Copies the authentication details from a source Authentication object to a destination one, provided the
     * latter does not already have one set.
     *
     * @param source source authentication
     * @param dest the destination authentication object
     */
    private void copyDetails(Authentication source, Authentication dest) {
        if ((dest instanceof AbstractAuthenticationToken) && (dest.getDetails() == null)) {
            AbstractAuthenticationToken token = (AbstractAuthenticationToken) dest;

            token.setDetails(source.getDetails());
        }
    }

    public List getProviders() {
        if (providers == null || providers.size() == 0) {
            throw new IllegalArgumentException("A list of AuthenticationProviders is required");
        }

        return providers;
    }

    /**
     * The configured {@link ConcurrentSessionController} is returned or the {@link
     * NullConcurrentSessionController} if a specific one has not been set.
     *
     * @return {@link ConcurrentSessionController} instance
     */
    public ConcurrentSessionController getSessionController() {
        return sessionController;
    }

    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.applicationEventPublisher = applicationEventPublisher;
    }

    public void setMessageSource(MessageSource messageSource) {
        this.messages = new MessageSourceAccessor(messageSource);
    }

    /**
     * Sets the {@link AuthenticationProvider} objects to be used for authentication.
     *
     * @param providers the list of authentication providers which will be used to process authentication requests.
     *
     * @throws IllegalArgumentException if the list is empty or null, or any of the elements in the list is not an
     * AuthenticationProvider instance.
     */
    public void setProviders(List providers) {
    	Assert.notEmpty(providers, "A list of AuthenticationProviders is required");
        Iterator iter = providers.iterator();

        while (iter.hasNext()) {
            Object currentObject = iter.next();
            Assert.isInstanceOf(AuthenticationProvider.class, currentObject,
                    "Can only provide AuthenticationProvider instances");
        }

        this.providers = providers;
    }

    /**
     * Set the {@link ConcurrentSessionController} to be used for limiting users' sessions. The {@link
     * NullConcurrentSessionController} is used by default.
     *
     * @param sessionController {@link ConcurrentSessionController}
     */
    public void setSessionController(ConcurrentSessionController sessionController) {
        this.sessionController = sessionController;
    }

    private void publishEvent(ApplicationEvent event) {
        if (applicationEventPublisher != null) {
            applicationEventPublisher.publishEvent(event);
        }
    }

    /**
     * Sets additional exception to event mappings. These are automatically merged with the default
     * exception to event mappings that <code>ProviderManager</code> defines.
     *
     * @param additionalExceptionMappings where keys are the fully-qualified string name of the exception class and the
     * values are the fully-qualified string name of the event class to fire.
     */
    public void setAdditionalExceptionMappings(Properties additionalExceptionMappings) {
        this.additionalExceptionMappings = additionalExceptionMappings;
    }
}
