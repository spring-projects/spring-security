/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.authorization;

import java.util.function.Supplier;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationConvention;
import io.micrometer.observation.ObservationRegistry;
import org.aopalliance.intercept.MethodInvocation;

import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.method.MethodAuthorizationDeniedHandler;
import org.springframework.security.authorization.method.MethodInvocationResult;
import org.springframework.security.authorization.method.ThrowingMethodAuthorizationDeniedHandler;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.util.Assert;

/**
 * An {@link AuthorizationManager} that observes the authorization
 *
 * @author Josh Cummings
 * @since 6.0
 */
public final class ObservationAuthorizationManager<T>
		implements AuthorizationManager<T>, MessageSourceAware, MethodAuthorizationDeniedHandler {

	private final ObservationRegistry registry;

	private final AuthorizationManager<T> delegate;

	private ObservationConvention<AuthorizationObservationContext<?>> convention = new AuthorizationObservationConvention();

	private MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

	private MethodAuthorizationDeniedHandler handler = new ThrowingMethodAuthorizationDeniedHandler();

	public ObservationAuthorizationManager(ObservationRegistry registry, AuthorizationManager<T> delegate) {
		this.registry = registry;
		this.delegate = delegate;
		if (delegate instanceof MethodAuthorizationDeniedHandler h) {
			this.handler = h;
		}
	}

	/**
	 * @deprecated please use {@link #authorize(Supplier, Object)} instead
	 */
	@Deprecated
	@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication, T object) {
		AuthorizationObservationContext<T> context = new AuthorizationObservationContext<>(object);
		Supplier<Authentication> wrapped = () -> {
			context.setAuthentication(authentication.get());
			return context.getAuthentication();
		};
		Observation observation = Observation.createNotStarted(this.convention, () -> context, this.registry).start();
		try (Observation.Scope scope = observation.openScope()) {
			AuthorizationDecision decision = this.delegate.check(wrapped, object);
			context.setAuthorizationResult(decision);
			if (decision != null && !decision.isGranted()) {
				observation.error(new AccessDeniedException(
						this.messages.getMessage("AbstractAccessDecisionManager.accessDenied", "Access Denied")));
			}
			return decision;
		}
		catch (Throwable ex) {
			observation.error(ex);
			throw ex;
		}
		finally {
			observation.stop();
		}
	}

	/**
	 * Use the provided convention for reporting observation data
	 * @param convention The provided convention
	 *
	 * @since 6.1
	 */
	public void setObservationConvention(ObservationConvention<AuthorizationObservationContext<?>> convention) {
		Assert.notNull(convention, "The observation convention cannot be null");
		this.convention = convention;
	}

	/**
	 * Set the MessageSource that this object runs in.
	 * @param messageSource The message source to be used by this object
	 * @since 6.2
	 */
	@Override
	public void setMessageSource(final MessageSource messageSource) {
		this.messages = new MessageSourceAccessor(messageSource);
	}

	@Override
	public Object handleDeniedInvocation(MethodInvocation methodInvocation, AuthorizationResult authorizationResult) {
		return this.handler.handleDeniedInvocation(methodInvocation, authorizationResult);
	}

	@Override
	public Object handleDeniedInvocationResult(MethodInvocationResult methodInvocationResult,
			AuthorizationResult authorizationResult) {
		return this.handler.handleDeniedInvocationResult(methodInvocationResult, authorizationResult);
	}

}
