package org.springframework.security.authentication;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationFailureCredentialsExpiredEvent;
import org.springframework.security.authentication.event.AuthenticationFailureDisabledEvent;
import org.springframework.security.authentication.event.AuthenticationFailureExpiredEvent;
import org.springframework.security.authentication.event.AuthenticationFailureLockedEvent;
import org.springframework.security.authentication.event.AuthenticationFailureProviderNotFoundEvent;
import org.springframework.security.authentication.event.AuthenticationFailureProxyUntrustedEvent;
import org.springframework.security.authentication.event.AuthenticationFailureServiceExceptionEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;

/**
 * The default strategy for publishing authentication events.
 * <p>
 * Maps well-known <tt>AuthenticationException</tt> types to events and publishes them via the
 * application context. If configured as a bean, it will pick up the <tt>ApplicationEventPublisher</tt> automatically.
 * Otherwise, the constructor which takes the publisher as an argument should be used.
 * <p>
 * The exception-mapping system can be fine-tuned by setting the <tt>additionalExceptionMappings</tt> as a
 * <code>java.util.Properties</code> object. In the properties object, each of the keys represent the fully qualified
 * classname of the exception, and each of the values represent the name of an event class which subclasses
 * {@link org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent}
 * and provides its constructor. The <tt>additionalExceptionMappings</tt> will be merged with the default ones.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public class DefaultAuthenticationEventPublisher implements AuthenticationEventPublisher,
        ApplicationEventPublisherAware {
    private final Log logger = LogFactory.getLog(getClass());

    private ApplicationEventPublisher applicationEventPublisher;
    private final Properties exceptionMappings;

    public DefaultAuthenticationEventPublisher() {
        this(null);
    }

    public DefaultAuthenticationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.applicationEventPublisher = applicationEventPublisher;
        exceptionMappings = new Properties();
        exceptionMappings.put(AccountExpiredException.class.getName(),
                AuthenticationFailureExpiredEvent.class.getName());
        exceptionMappings.put(AuthenticationServiceException.class.getName(),
                AuthenticationFailureServiceExceptionEvent.class.getName());
        exceptionMappings.put(LockedException.class.getName(),
                AuthenticationFailureLockedEvent.class.getName());
        exceptionMappings.put(CredentialsExpiredException.class.getName(),
                AuthenticationFailureCredentialsExpiredEvent.class.getName());
        exceptionMappings.put(DisabledException.class.getName(),
                AuthenticationFailureDisabledEvent.class.getName());
        exceptionMappings.put(BadCredentialsException.class.getName(),
                AuthenticationFailureBadCredentialsEvent.class.getName());
        exceptionMappings.put(UsernameNotFoundException.class.getName(),
                AuthenticationFailureBadCredentialsEvent.class.getName());
        exceptionMappings.put(ProviderNotFoundException.class.getName(),
                AuthenticationFailureProviderNotFoundEvent.class.getName());
        exceptionMappings.put("org.springframework.security.authentication.cas.ProxyUntrustedException",
                AuthenticationFailureProxyUntrustedEvent.class.getName());
    }

    public void publishAuthenticationSuccess(Authentication authentication) {
        if (applicationEventPublisher != null) {
            applicationEventPublisher.publishEvent(new AuthenticationSuccessEvent(authentication));
        }
    }

    public void publishAuthenticationFailure(AuthenticationException exception,
            Authentication authentication) {
        String className = exceptionMappings.getProperty(exception.getClass().getName());
        AbstractAuthenticationEvent event = null;

        if (className != null) {
            try {
                Class<?> clazz = getClass().getClassLoader().loadClass(className);
                Constructor<?> constructor = clazz.getConstructor(new Class[] {
                            Authentication.class, AuthenticationException.class
                        });
                Object obj = constructor.newInstance(authentication, exception);
                Assert.isInstanceOf(AbstractAuthenticationEvent.class, obj, "Must be an AbstractAuthenticationEvent");
                event = (AbstractAuthenticationEvent) obj;
            } catch (ClassNotFoundException ignored) {}
            catch (NoSuchMethodException ignored) {}
            catch (IllegalAccessException ignored) {}
            catch (InstantiationException ignored) {}
            catch (InvocationTargetException ignored) {}
        }

        if (event != null) {
            if (applicationEventPublisher != null) {
                applicationEventPublisher.publishEvent(event);
            }
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug("No event was found for the exception " + exception.getClass().getName());
            }
        }
    }

    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.applicationEventPublisher = applicationEventPublisher;
    }

    /**
     * Sets additional exception to event mappings. These are automatically merged with the default
     * exception to event mappings that <code>ProviderManager</code> defines.
     *
     * @param additionalExceptionMappings where keys are the fully-qualified string name of the exception class and the
     * values are the fully-qualified string name of the event class to fire.
     */
    public void setAdditionalExceptionMappings(Properties additionalExceptionMappings) {
        Assert.notNull(additionalExceptionMappings, "The exceptionMappings object must not be null");
        exceptionMappings.putAll(additionalExceptionMappings);
    }
}
