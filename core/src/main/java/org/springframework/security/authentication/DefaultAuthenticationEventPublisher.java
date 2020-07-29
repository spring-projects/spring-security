/*
 * Copyright 2002-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.authentication;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
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
 * Maps well-known <tt>AuthenticationException</tt> types to events and publishes them via
 * the application context. If configured as a bean, it will pick up the
 * <tt>ApplicationEventPublisher</tt> automatically. Otherwise, the constructor which
 * takes the publisher as an argument should be used.
 * <p>
 * The exception-mapping system can be fine-tuned by setting the
 * <tt>additionalExceptionMappings</tt> as a <code>java.util.Properties</code> object. In
 * the properties object, each of the keys represent the fully qualified classname of the
 * exception, and each of the values represent the name of an event class which subclasses
 * {@link org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent}
 * and provides its constructor. The <tt>additionalExceptionMappings</tt> will be merged
 * with the default ones.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class DefaultAuthenticationEventPublisher
		implements AuthenticationEventPublisher, ApplicationEventPublisherAware {

	private final Log logger = LogFactory.getLog(getClass());

	private ApplicationEventPublisher applicationEventPublisher;

	private final HashMap<String, Constructor<? extends AbstractAuthenticationEvent>> exceptionMappings = new HashMap<>();

	private Constructor<? extends AbstractAuthenticationFailureEvent> defaultAuthenticationFailureEventConstructor;

	public DefaultAuthenticationEventPublisher() {
		this(null);
	}

	public DefaultAuthenticationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
		this.applicationEventPublisher = applicationEventPublisher;

		addMapping(BadCredentialsException.class.getName(), AuthenticationFailureBadCredentialsEvent.class);
		addMapping(UsernameNotFoundException.class.getName(), AuthenticationFailureBadCredentialsEvent.class);
		addMapping(AccountExpiredException.class.getName(), AuthenticationFailureExpiredEvent.class);
		addMapping(ProviderNotFoundException.class.getName(), AuthenticationFailureProviderNotFoundEvent.class);
		addMapping(DisabledException.class.getName(), AuthenticationFailureDisabledEvent.class);
		addMapping(LockedException.class.getName(), AuthenticationFailureLockedEvent.class);
		addMapping(AuthenticationServiceException.class.getName(), AuthenticationFailureServiceExceptionEvent.class);
		addMapping(CredentialsExpiredException.class.getName(), AuthenticationFailureCredentialsExpiredEvent.class);
		addMapping("org.springframework.security.authentication.cas.ProxyUntrustedException",
				AuthenticationFailureProxyUntrustedEvent.class);
		addMapping("org.springframework.security.oauth2.server.resource.InvalidBearerTokenException",
				AuthenticationFailureBadCredentialsEvent.class);
	}

	@Override
	public void publishAuthenticationSuccess(Authentication authentication) {
		if (this.applicationEventPublisher != null) {
			this.applicationEventPublisher.publishEvent(new AuthenticationSuccessEvent(authentication));
		}
	}

	@Override
	public void publishAuthenticationFailure(AuthenticationException exception, Authentication authentication) {
		Constructor<? extends AbstractAuthenticationEvent> constructor = getEventConstructor(exception);
		AbstractAuthenticationEvent event = null;

		if (constructor != null) {
			try {
				event = constructor.newInstance(authentication, exception);
			}
			catch (IllegalAccessException | InvocationTargetException | InstantiationException ignored) {
			}
		}

		if (event != null) {
			if (this.applicationEventPublisher != null) {
				this.applicationEventPublisher.publishEvent(event);
			}
		}
		else {
			if (this.logger.isDebugEnabled()) {
				this.logger.debug("No event was found for the exception " + exception.getClass().getName());
			}
		}
	}

	private Constructor<? extends AbstractAuthenticationEvent> getEventConstructor(AuthenticationException exception) {
		Constructor<? extends AbstractAuthenticationEvent> eventConstructor = this.exceptionMappings
				.get(exception.getClass().getName());
		return (eventConstructor == null ? this.defaultAuthenticationFailureEventConstructor : eventConstructor);
	}

	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
		this.applicationEventPublisher = applicationEventPublisher;
	}

	/**
	 * Sets additional exception to event mappings. These are automatically merged with
	 * the default exception to event mappings that <code>ProviderManager</code> defines.
	 * @param additionalExceptionMappings where keys are the fully-qualified string name
	 * of the exception class and the values are the fully-qualified string name of the
	 * event class to fire.
	 * @deprecated use {@link #setAdditionalExceptionMappings(Map)}
	 */
	@Deprecated
	@SuppressWarnings({ "unchecked" })
	public void setAdditionalExceptionMappings(Properties additionalExceptionMappings) {
		Assert.notNull(additionalExceptionMappings, "The exceptionMappings object must not be null");
		for (Object exceptionClass : additionalExceptionMappings.keySet()) {
			String eventClass = (String) additionalExceptionMappings.get(exceptionClass);
			try {
				Class<?> clazz = getClass().getClassLoader().loadClass(eventClass);
				Assert.isAssignable(AbstractAuthenticationFailureEvent.class, clazz);
				addMapping((String) exceptionClass, (Class<? extends AbstractAuthenticationFailureEvent>) clazz);
			}
			catch (ClassNotFoundException ex) {
				throw new RuntimeException("Failed to load authentication event class " + eventClass);
			}
		}
	}

	/**
	 * Sets additional exception to event mappings. These are automatically merged with
	 * the default exception to event mappings that <code>ProviderManager</code> defines.
	 * @param mappings where keys are exception classes and values are event classes.
	 * @since 5.3
	 */
	public void setAdditionalExceptionMappings(
			Map<Class<? extends AuthenticationException>, Class<? extends AbstractAuthenticationFailureEvent>> mappings) {
		Assert.notEmpty(mappings, "The mappings Map must not be empty nor null");
		for (Map.Entry<Class<? extends AuthenticationException>, Class<? extends AbstractAuthenticationFailureEvent>> entry : mappings
				.entrySet()) {
			Class<?> exceptionClass = entry.getKey();
			Class<?> eventClass = entry.getValue();
			Assert.notNull(exceptionClass, "exceptionClass cannot be null");
			Assert.notNull(eventClass, "eventClass cannot be null");
			addMapping(exceptionClass.getName(), (Class<? extends AbstractAuthenticationFailureEvent>) eventClass);
		}
	}

	/**
	 * Sets a default authentication failure event as a fallback event for any unmapped
	 * exceptions not mapped in the exception mappings.
	 * @param defaultAuthenticationFailureEventClass is the authentication failure event
	 * class to be fired for unmapped exceptions.
	 */
	public void setDefaultAuthenticationFailureEvent(
			Class<? extends AbstractAuthenticationFailureEvent> defaultAuthenticationFailureEventClass) {
		Assert.notNull(defaultAuthenticationFailureEventClass,
				"defaultAuthenticationFailureEventClass must not be null");
		try {
			this.defaultAuthenticationFailureEventConstructor = defaultAuthenticationFailureEventClass
					.getConstructor(Authentication.class, AuthenticationException.class);
		}
		catch (NoSuchMethodException ex) {
			throw new RuntimeException("Default Authentication Failure event class "
					+ defaultAuthenticationFailureEventClass.getName() + " has no suitable constructor");
		}
	}

	private void addMapping(String exceptionClass, Class<? extends AbstractAuthenticationFailureEvent> eventClass) {
		try {
			Constructor<? extends AbstractAuthenticationEvent> constructor = eventClass
					.getConstructor(Authentication.class, AuthenticationException.class);
			this.exceptionMappings.put(exceptionClass, constructor);
		}
		catch (NoSuchMethodException ex) {
			throw new RuntimeException(
					"Authentication event class " + eventClass.getName() + " has no suitable constructor");
		}
	}

}
