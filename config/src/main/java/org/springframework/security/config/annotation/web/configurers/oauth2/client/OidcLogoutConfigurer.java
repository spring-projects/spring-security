/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers.oauth2.client;

import java.util.function.Consumer;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.GenericApplicationListenerAdapter;
import org.springframework.context.event.SmartApplicationListener;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.context.DelegatingApplicationListener;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.AbstractSessionEvent;
import org.springframework.security.core.session.SessionDestroyedEvent;
import org.springframework.security.core.session.SessionIdChangedEvent;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcBackChannelLogoutAuthenticationManager;
import org.springframework.security.oauth2.client.oidc.authentication.session.InMemoryOidcSessionRegistry;
import org.springframework.security.oauth2.client.oidc.authentication.session.OidcSessionRegistration;
import org.springframework.security.oauth2.client.oidc.authentication.session.OidcSessionRegistry;
import org.springframework.security.oauth2.client.oidc.web.authentication.logout.OidcBackChannelLogoutFilter;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.logout.BackchannelLogoutAuthentication;
import org.springframework.security.web.authentication.logout.BackchannelLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.util.Assert;

/**
 * An {@link AbstractHttpConfigurer} for OAuth 2.0 Logout flows
 *
 * <p>
 * OAuth 2.0 Logout provides an application with the capability to have users log out by
 * using their existing account at an OAuth 2.0 or OpenID Connect 1.0 Provider.
 *
 *
 * <h2>Security Filters</h2>
 *
 * The following {@code Filter} is populated:
 *
 * <ul>
 * <li>{@link OidcBackChannelLogoutFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 * <li>{@link ClientRegistrationRepository}</li>
 * </ul>
 *
 * @author Josh Cummings
 * @since 6.1
 * @see HttpSecurity#oauth2Logout()
 * @see OidcBackChannelLogoutFilter
 * @see ClientRegistrationRepository
 */
public final class OidcLogoutConfigurer<B extends HttpSecurityBuilder<B>>
		extends AbstractHttpConfigurer<OidcLogoutConfigurer<B>, B> {

	private BackChannelLogoutConfigurer backChannel;

	/**
	 * Sets the repository of client registrations.
	 * @param clientRegistrationRepository the repository of client registrations
	 * @return the {@link OidcLogoutConfigurer} for further configuration
	 */
	public OidcLogoutConfigurer<B> backChannel(Consumer<BackChannelLogoutConfigurer> backChannelLogoutConfigurer) {
		if (this.backChannel == null) {
			this.backChannel = new BackChannelLogoutConfigurer();
		}
		backChannelLogoutConfigurer.accept(this.backChannel);
		return this;
	}

	public B and() {
		return getBuilder();
	}

	@Override
	public void configure(B builder) throws Exception {
		if (this.backChannel != null) {
			this.backChannel.configure(builder);
		}
	}

	private void registerDelegateApplicationListener(ApplicationListener<?> delegate) {
		DelegatingApplicationListener delegating = getBeanOrNull(DelegatingApplicationListener.class);
		if (delegating == null) {
			return;
		}
		SmartApplicationListener smartListener = new GenericApplicationListenerAdapter(delegate);
		delegating.addListener(smartListener);
	}

	private <T> T getBeanOrNull(Class<T> type) {
		ApplicationContext context = getBuilder().getSharedObject(ApplicationContext.class);
		if (context == null) {
			return null;
		}
		try {
			return context.getBean(type);
		}
		catch (NoSuchBeanDefinitionException ex) {
			return null;
		}
	}

	public final class BackChannelLogoutConfigurer {

		private LogoutHandler logoutHandler = new BackchannelLogoutHandler();

		private AuthenticationManager authenticationManager = new OidcBackChannelLogoutAuthenticationManager();

		private OidcSessionRegistry providerSessionRegistry = new InMemoryOidcSessionRegistry();

		public BackChannelLogoutConfigurer clientLogoutHandler(LogoutHandler logoutHandler) {
			Assert.notNull(logoutHandler, "logoutHandler cannot be null");
			this.logoutHandler = logoutHandler;
			return this;
		}

		public BackChannelLogoutConfigurer authenticationManager(AuthenticationManager authenticationManager) {
			Assert.notNull(authenticationManager, "authenticationManager cannot be null");
			this.authenticationManager = authenticationManager;
			return this;
		}

		public BackChannelLogoutConfigurer oidcProviderSessionRegistry(OidcSessionRegistry providerSessionRegistry) {
			Assert.notNull(providerSessionRegistry, "providerSessionRegistry cannot be null");
			this.providerSessionRegistry = providerSessionRegistry;
			return this;
		}

		private AuthenticationManager authenticationManager() {
			return this.authenticationManager;
		}

		private OidcSessionRegistry oidcProviderSessionRegistry() {
			return this.providerSessionRegistry;
		}

		private LogoutHandler logoutHandler() {
			return this.logoutHandler;
		}

		private SessionAuthenticationStrategy sessionAuthenticationStrategy() {
			OidcProviderSessionAuthenticationStrategy strategy = new OidcProviderSessionAuthenticationStrategy();
			strategy.setProviderSessionRegistry(oidcProviderSessionRegistry());
			return strategy;
		}

		void configure(B http) {
			ClientRegistrationRepository clientRegistrationRepository = OAuth2ClientConfigurerUtils
					.getClientRegistrationRepository(http);
			OidcBackChannelLogoutFilter filter = new OidcBackChannelLogoutFilter(clientRegistrationRepository,
					authenticationManager());
			filter.setProviderSessionRegistry(oidcProviderSessionRegistry());
			LogoutHandler expiredStrategy = logoutHandler();
			filter.setLogoutHandler(expiredStrategy);
			http.addFilterBefore(filter, CsrfFilter.class);
			SessionManagementConfigurer<B> sessionConfigurer = http.getConfigurer(SessionManagementConfigurer.class);
			if (sessionConfigurer != null) {
				sessionConfigurer.addSessionAuthenticationStrategy(sessionAuthenticationStrategy());
			}
			OidcClientSessionEventListener listener = new OidcClientSessionEventListener();
			listener.setProviderSessionRegistry(this.providerSessionRegistry);
			registerDelegateApplicationListener(listener);
		}

		static final class OidcClientSessionEventListener implements ApplicationListener<AbstractSessionEvent> {

			private final Log logger = LogFactory.getLog(OidcClientSessionEventListener.class);

			private OidcSessionRegistry providerSessionRegistry = new InMemoryOidcSessionRegistry();

			/**
			 * {@inheritDoc}
			 */
			@Override
			public void onApplicationEvent(AbstractSessionEvent event) {
				if (event instanceof SessionDestroyedEvent destroyed) {
					this.logger.debug("Received SessionDestroyedEvent");
					this.providerSessionRegistry.deregister(destroyed.getId());
					return;
				}
				if (event instanceof SessionIdChangedEvent changed) {
					this.logger.debug("Received SessionIdChangedEvent");
					this.providerSessionRegistry.register(changed.getOldSessionId(), changed.getNewSessionId());
				}
			}

			/**
			 * The registry where OIDC Provider sessions are linked to the Client session.
			 * Defaults to in-memory storage.
			 * @param providerSessionRegistry the {@link OidcSessionRegistry} to use
			 */
			void setProviderSessionRegistry(OidcSessionRegistry providerSessionRegistry) {
				Assert.notNull(providerSessionRegistry, "providerSessionRegistry cannot be null");
				this.providerSessionRegistry = providerSessionRegistry;
			}

		}

		static final class OidcProviderSessionAuthenticationStrategy implements SessionAuthenticationStrategy {

			private final Log logger = LogFactory.getLog(getClass());

			private OidcSessionRegistry providerSessionRegistry = new InMemoryOidcSessionRegistry();

			/**
			 * {@inheritDoc}
			 */
			@Override
			public void onAuthentication(Authentication authentication, HttpServletRequest request, HttpServletResponse response) throws SessionAuthenticationException {
				HttpSession session = request.getSession(false);
				if (session == null) {
					return;
				}
				if (authentication == null) {
					return;
				}
				if (!(authentication.getPrincipal() instanceof OidcUser user)) {
					return;
				}
				String sessionId = session.getId();
				CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
				BackchannelLogoutAuthentication logoutAuthentication = new BackchannelLogoutAuthentication(sessionId, csrfToken);
				OidcSessionRegistration registration = new OidcSessionRegistration(sessionId, user, logoutAuthentication);
				if (this.logger.isTraceEnabled()) {
					this.logger.trace(String.format("Linking a provider [%s] session to this client's session", user.getIssuer()));
				}
				this.providerSessionRegistry.register(registration);
			}

			/**
			 * The registration for linking OIDC Provider Session information to the
			 * Client's session. Defaults to in-memory.
			 * @param providerSessionRegistry the {@link OidcSessionRegistry} to use
			 */
			void setProviderSessionRegistry(OidcSessionRegistry providerSessionRegistry) {
				Assert.notNull(providerSessionRegistry, "providerSessionRegistry cannot be null");
				this.providerSessionRegistry = providerSessionRegistry;
			}

		}

	}

}
