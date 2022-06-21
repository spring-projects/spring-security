/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.messaging.access.intercept;

import java.util.function.Supplier;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationEventPublisher;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.util.Assert;

/**
 * Authorizes {@link Message} resources using the provided {@link AuthorizationManager}
 *
 * @author Josh Cummings
 * @since 5.8
 */
public final class AuthorizationChannelInterceptor implements ChannelInterceptor {

	private Supplier<Authentication> authentication = getAuthentication(
			SecurityContextHolder.getContextHolderStrategy());

	private final Log logger = LogFactory.getLog(this.getClass());

	private final AuthorizationManager<Message<?>> preSendAuthorizationManager;

	private AuthorizationEventPublisher eventPublisher = new NoopAuthorizationEventPublisher();

	/**
	 * Creates a new instance
	 * @param preSendAuthorizationManager the {@link AuthorizationManager} to use. Cannot
	 * be null.
	 *
	 */
	public AuthorizationChannelInterceptor(AuthorizationManager<Message<?>> preSendAuthorizationManager) {
		Assert.notNull(preSendAuthorizationManager, "preSendAuthorizationManager cannot be null");
		this.preSendAuthorizationManager = preSendAuthorizationManager;
	}

	@Override
	public Message<?> preSend(Message<?> message, MessageChannel channel) {
		this.logger.debug(LogMessage.of(() -> "Authorizing message send"));
		AuthorizationDecision decision = this.preSendAuthorizationManager.check(this.authentication, message);
		this.eventPublisher.publishAuthorizationEvent(this.authentication, message, decision);
		if (decision == null || !decision.isGranted()) { // default deny
			this.logger.debug(LogMessage.of(() -> "Failed to authorize message with authorization manager "
					+ this.preSendAuthorizationManager + " and decision " + decision));
			throw new AccessDeniedException("Access Denied");
		}
		this.logger.debug(LogMessage.of(() -> "Authorized message send"));
		return message;
	}

	/**
	 * Sets the {@link SecurityContextHolderStrategy} to use. The default action is to use
	 * the {@link SecurityContextHolderStrategy} stored in {@link SecurityContextHolder}.
	 */
	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		this.authentication = getAuthentication(securityContextHolderStrategy);
	}

	/**
	 * Use this {@link AuthorizationEventPublisher} to publish the
	 * {@link AuthorizationManager} result.
	 * @param eventPublisher
	 */
	public void setAuthorizationEventPublisher(AuthorizationEventPublisher eventPublisher) {
		Assert.notNull(eventPublisher, "eventPublisher cannot be null");
		this.eventPublisher = eventPublisher;
	}

	private Supplier<Authentication> getAuthentication(SecurityContextHolderStrategy strategy) {
		return () -> {
			Authentication authentication = strategy.getContext().getAuthentication();
			if (authentication == null) {
				throw new AuthenticationCredentialsNotFoundException(
						"An Authentication object was not found in the SecurityContext");
			}
			return authentication;
		};
	}

	private static class NoopAuthorizationEventPublisher implements AuthorizationEventPublisher {

		@Override
		public <T> void publishAuthorizationEvent(Supplier<Authentication> authentication, T object,
				AuthorizationDecision decision) {

		}

	}

}
