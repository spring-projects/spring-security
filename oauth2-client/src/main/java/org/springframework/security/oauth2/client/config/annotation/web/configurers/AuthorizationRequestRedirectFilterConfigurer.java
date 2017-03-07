/*
 * Copyright 2012-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client.config.annotation.web.configurers;

import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.authorization.AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.authorization.AuthorizationRequestUriBuilder;
import org.springframework.security.oauth2.client.authorization.DefaultAuthorizationRequestUriBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.util.Assert;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

import static org.springframework.security.oauth2.client.config.annotation.web.configurers.OAuth2LoginSecurityConfigurer.getDefaultClientRegistrationRepository;

/**
 * @author Joe Grandja
 */
final class AuthorizationRequestRedirectFilterConfigurer<B extends HttpSecurityBuilder<B>> extends
		AbstractHttpConfigurer<AuthorizationRequestRedirectFilterConfigurer<B>, B> {

	private String authorizationProcessingUri;

	private AuthorizationRequestUriBuilder authorizationRequestBuilder;

	AuthorizationRequestRedirectFilterConfigurer<B> clientRegistrationRepository(ClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notEmpty(clientRegistrationRepository.getRegistrations(), "clientRegistrationRepository cannot be empty");
		this.getBuilder().setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
		return this;
	}

	AuthorizationRequestRedirectFilterConfigurer<B> authorizationProcessingUri(String authorizationProcessingUri) {
		Assert.notNull(authorizationProcessingUri, "authorizationProcessingUri cannot be null");
		this.authorizationProcessingUri = authorizationProcessingUri;
		return this;
	}

	AuthorizationRequestRedirectFilterConfigurer<B> authorizationRequestBuilder(AuthorizationRequestUriBuilder authorizationRequestBuilder) {
		Assert.notNull(authorizationRequestBuilder, "authorizationRequestBuilder cannot be null");
		this.authorizationRequestBuilder = authorizationRequestBuilder;
		return this;
	}

	@Override
	public void configure(B http) throws Exception {
		AuthorizationRequestRedirectFilter filter = new AuthorizationRequestRedirectFilter(
				this.getAuthorizationProcessingUri(),
				this.getClientRegistrationRepository(),
				this.getAuthorizationRequestBuilder());

		// TODO Temporary workaround
		// 		Remove this after we add an order in FilterComparator for AuthorizationRequestRedirectFilter
		this.addObjectPostProcessor(new OrderedFilterWrappingPostProcessor());

		http.addFilter(this.postProcess(filter));
	}

	String getAuthorizationProcessingUri() {
		return (this.authorizationProcessingUri != null ?
				this.authorizationProcessingUri : AuthorizationRequestRedirectFilter.DEFAULT_FILTER_PROCESSING_URI);
	}

	private ClientRegistrationRepository getClientRegistrationRepository() {
		ClientRegistrationRepository clientRegistrationRepository = this.getBuilder().getSharedObject(ClientRegistrationRepository.class);
		if (clientRegistrationRepository == null) {
			clientRegistrationRepository = getDefaultClientRegistrationRepository(this.getBuilder().getSharedObject(ApplicationContext.class));
			this.getBuilder().setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
		}
		return clientRegistrationRepository;
	}

	private AuthorizationRequestUriBuilder getAuthorizationRequestBuilder() {
		if (this.authorizationRequestBuilder == null) {
			this.authorizationRequestBuilder = new DefaultAuthorizationRequestUriBuilder();
		}
		return this.authorizationRequestBuilder;
	}

	// TODO Temporary workaround
	// 		Remove this after we add an order in FilterComparator for AuthorizationRequestRedirectFilter
	private final class OrderedFilterWrappingPostProcessor implements ObjectPostProcessor<Object> {

		@SuppressWarnings({ "rawtypes", "unchecked" })
		public Object postProcess(final Object delegateFilter) {
			AbstractPreAuthenticatedProcessingFilter orderedFilter = new AbstractPreAuthenticatedProcessingFilter() {

				@Override
				public void doFilter(ServletRequest request, ServletResponse response,
										FilterChain chain) throws IOException, ServletException {

					((AuthorizationRequestRedirectFilter)delegateFilter).doFilter(request, response, chain);
				}

				@Override
				protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
					return null;
				}

				@Override
				protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
					return null;
				}
			};
			return orderedFilter;
		}
	}
}
