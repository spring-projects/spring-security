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

import java.util.Collections;
import java.util.Map;
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
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.context.DelegatingApplicationListener;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.AbstractSessionEvent;
import org.springframework.security.core.session.SessionDestroyedEvent;
import org.springframework.security.core.session.SessionIdChangedEvent;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcBackChannelLogoutAuthenticationProvider;
import org.springframework.security.oauth2.client.oidc.session.InMemoryOidcSessionRegistry;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionInformation;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionRegistry;
import org.springframework.security.oauth2.client.oidc.web.OidcBackChannelLogoutFilter;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcBackChannelLogoutHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.util.Assert;

/**
 * An {@link AbstractHttpConfigurer} for OIDC Logout flows
 *
 * <p>
 * OIDC Logout provides an application with the capability to have users log out by using
 * their existing account at an OAuth 2.0 or OpenID Connect 1.0 Provider.
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
 * @since 6.2
 * @see HttpSecurity#oidcLogout()
 * @see OidcBackChannelLogoutFilter
 * @see ClientRegistrationRepository
 */
public final class OidcLogoutConfigurer<B extends HttpSecurityBuilder<B>>
		extends AbstractHttpConfigurer<OidcLogoutConfigurer<B>, B> {

	private BackChannelLogoutConfigurer backChannel;

	/**
	 * Configure OIDC Back-Channel Logout using the provided {@link Consumer}
	 * @return the {@link OidcLogoutConfigurer} for further configuration
	 */
	public OidcLogoutConfigurer<B> backChannel(Customizer<BackChannelLogoutConfigurer> backChannelLogoutConfigurer) {
		if (this.backChannel == null) {
			this.backChannel = new BackChannelLogoutConfigurer();
		}
		backChannelLogoutConfigurer.customize(this.backChannel);
		return this;
	}

	@Deprecated(forRemoval = true, since = "6.2")
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

	/**
	 * A configurer for configuring OIDC Back-Channel Logout
	 */
	public final class BackChannelLogoutConfigurer {

		private AuthenticationManager authenticationManager = new ProviderManager(
				new OidcBackChannelLogoutAuthenticationProvider());

		private OidcSessionRegistry sessionRegistry = new InMemoryOidcSessionRegistry();

		private LogoutHandler logoutHandler;

		/**
		 * Use this {@link AuthenticationManager} to authenticate the OIDC Logout Token
		 * @param authenticationManager the {@link AuthenticationManager} to use
		 * @return the {@link BackChannelLogoutConfigurer} for further configuration
		 */
		public BackChannelLogoutConfigurer authenticationManager(AuthenticationManager authenticationManager) {
			Assert.notNull(authenticationManager, "authenticationManager cannot be null");
			this.authenticationManager = authenticationManager;
			return this;
		}

		/**
		 * Use this {@link OidcSessionRegistry} for managing the client-provider session
		 * link
		 * @param sessionRegistry the {@link OidcSessionRegistry} to use
		 * @return the {@link BackChannelLogoutConfigurer} for further configuration
		 */
		public BackChannelLogoutConfigurer oidcSessionRegistry(OidcSessionRegistry sessionRegistry) {
			Assert.notNull(sessionRegistry, "sessionRegistry cannot be null");
			this.sessionRegistry = sessionRegistry;
			return this;
		}

		/**
		 * Use this {@link LogoutHandler} for invalidating each session identified by the
		 * OIDC Back-Channel Logout Token
		 * @return the {@link BackChannelLogoutConfigurer} for further configuration
		 */
		public BackChannelLogoutConfigurer logoutHandler(LogoutHandler logoutHandler) {
			Assert.notNull(logoutHandler, "logoutHandler cannot be null");
			this.logoutHandler = logoutHandler;
			return this;
		}

		private AuthenticationManager authenticationManager() {
			return this.authenticationManager;
		}

		private OidcSessionRegistry oidcSessionRegistry() {
			return this.sessionRegistry;
		}

		private LogoutHandler logoutHandler() {
			if (this.logoutHandler == null) {
				OidcBackChannelLogoutHandler logoutHandler = new OidcBackChannelLogoutHandler();
				logoutHandler.setSessionRegistry(this.sessionRegistry);
				this.logoutHandler = logoutHandler;
			}
			return this.logoutHandler;
		}

		private SessionAuthenticationStrategy sessionAuthenticationStrategy() {
			OidcSessionRegistryAuthenticationStrategy strategy = new OidcSessionRegistryAuthenticationStrategy();
			strategy.setSessionRegistry(oidcSessionRegistry());
			return strategy;
		}

		void configure(B http) {
			ClientRegistrationRepository clientRegistrationRepository = OAuth2ClientConfigurerUtils
					.getClientRegistrationRepository(http);
			OidcBackChannelLogoutFilter filter = new OidcBackChannelLogoutFilter(clientRegistrationRepository,
					authenticationManager());
			filter.setLogoutHandler(logoutHandler());
			http.addFilterBefore(filter, CsrfFilter.class);
			SessionManagementConfigurer<B> sessionConfigurer = http.getConfigurer(SessionManagementConfigurer.class);
			if (sessionConfigurer != null) {
				sessionConfigurer.addSessionAuthenticationStrategy(sessionAuthenticationStrategy());
			}
			OidcClientSessionEventListener listener = new OidcClientSessionEventListener();
			listener.setSessionRegistry(this.sessionRegistry);
			registerDelegateApplicationListener(listener);
		}

		static final class OidcClientSessionEventListener implements ApplicationListener<AbstractSessionEvent> {

			private final Log logger = LogFactory.getLog(OidcClientSessionEventListener.class);

			private OidcSessionRegistry sessionRegistry = new InMemoryOidcSessionRegistry();

			/**
			 * {@inheritDoc}
			 */
			@Override
			public void onApplicationEvent(AbstractSessionEvent event) {
				if (event instanceof SessionDestroyedEvent destroyed) {
					this.logger.debug("Received SessionDestroyedEvent");
					this.sessionRegistry.removeSessionInformation(destroyed.getId());
					return;
				}
				if (event instanceof SessionIdChangedEvent changed) {
					this.logger.debug("Received SessionIdChangedEvent");
					OidcSessionInformation information = this.sessionRegistry.removeSessionInformation(changed.getOldSessionId());
					if (information == null) {
						this.logger.debug("Failed to register new session id since old session id was not found in registry");
						return;
					}
					this.sessionRegistry.saveSessionInformation(information.withSessionId(changed.getNewSessionId()));
				}
			}

			/**
			 * The registry where OIDC Provider sessions are linked to the Client session.
			 * Defaults to in-memory storage.
			 * @param sessionRegistry the {@link OidcSessionRegistry} to use
			 */
			void setSessionRegistry(OidcSessionRegistry sessionRegistry) {
				Assert.notNull(sessionRegistry, "sessionRegistry cannot be null");
				this.sessionRegistry = sessionRegistry;
			}

		}

		static final class OidcSessionRegistryAuthenticationStrategy implements SessionAuthenticationStrategy {

			private final Log logger = LogFactory.getLog(getClass());

			private OidcSessionRegistry sessionRegistry = new InMemoryOidcSessionRegistry();

			/**
			 * {@inheritDoc}
			 */
			@Override
			public void onAuthentication(Authentication authentication, HttpServletRequest request, HttpServletResponse response) throws SessionAuthenticationException {
				HttpSession session = request.getSession(false);
				if (session == null) {
					return;
				}
				if (!(authentication.getPrincipal() instanceof OidcUser user)) {
					return;
				}
				String sessionId = session.getId();
				CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
				Map<String, String> headers = (csrfToken != null) ? Map.of(csrfToken.getHeaderName(), csrfToken.getToken()) : Collections.emptyMap();
				OidcSessionInformation registration = new OidcSessionInformation(sessionId, headers, user);
				if (this.logger.isTraceEnabled()) {
					this.logger.trace(String.format("Linking a provider [%s] session to this client's session", user.getIssuer()));
				}
				this.sessionRegistry.saveSessionInformation(registration);
			}

			/**
			 * The registration for linking OIDC Provider Session information to the
			 * Client's session. Defaults to in-memory storage.
			 * @param sessionRegistry the {@link OidcSessionRegistry} to use
			 */
			void setSessionRegistry(OidcSessionRegistry sessionRegistry) {
				Assert.notNull(sessionRegistry, "sessionRegistry cannot be null");
				this.sessionRegistry = sessionRegistry;
			}

		}

	}

}
