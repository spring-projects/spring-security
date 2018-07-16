/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers.oauth2.server.resource;

import javax.servlet.http.HttpServletRequest;

import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderJwkSupport;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 *
 * An {@link AbstractHttpConfigurer} for OAuth 2.0 Resource Server Support.
 *
 * By default, this wires a {@link BearerTokenAuthenticationFilter}, which can be used to parse the request
 * for bearer tokens and make an authentication attempt.
 *
 * <p>
 * The following configuration options are available:
 *
 * <ul>
 * <li>{@link #jwt()} - enables Jwt-encoded bearer token support</li>
 * </ul>
 *
 * <p>
 * When using {@link #jwt()}, either
 *
 * <ul>
 * <li>
 * supply a Jwk Set Uri via {@link JwtConfigurer#jwkSetUri}, or
 * </li>
 * <li>
 * supply a {@link JwtDecoder} instance via {@link JwtConfigurer#decoder}, or
 * </li>
 * <li>
 * expose a {@link JwtDecoder} bean
 * </li>
 * </ul>
 *
 * <h2>Security Filters</h2>
 *
 * The following {@code Filter}s are populated when {@link #jwt()} is configured:
 *
 * <ul>
 * <li>{@link BearerTokenAuthenticationFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * The following shared objects are populated:
 *
 * <ul>
 * <li>{@link SessionCreationPolicy} (optional)</li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 * <li>{@link AuthenticationManager}</li>
 * </ul>
 *
 * @author Josh Cummings
 * @since 5.1
 * @see BearerTokenAuthenticationFilter
 * @see JwtAuthenticationProvider
 * @see NimbusJwtDecoderJwkSupport
 * @see AbstractHttpConfigurer
 */
public final class OAuth2ResourceServerConfigurer<H extends HttpSecurityBuilder<H>> extends
		AbstractHttpConfigurer<OAuth2ResourceServerConfigurer<H>, H> {

	private BearerTokenResolver bearerTokenResolver = new DefaultBearerTokenResolver();
	private BearerTokenRequestMatcher requestMatcher = new BearerTokenRequestMatcher();

	private BearerTokenAuthenticationEntryPoint authenticationEntryPoint
			= new BearerTokenAuthenticationEntryPoint();

	private BearerTokenAccessDeniedHandler accessDeniedHandler
			= new BearerTokenAccessDeniedHandler();

	private JwtConfigurer jwtConfigurer;

	public JwtConfigurer jwt() {
		if ( this.jwtConfigurer == null ) {
			ApplicationContext context = this.getBuilder().getSharedObject(ApplicationContext.class);
			this.jwtConfigurer = new JwtConfigurer(context);
		}

		return this.jwtConfigurer;
	}

	@Override
	public void setBuilder(H http) {
		super.setBuilder(http);
		initSessionCreationPolicy(http);
	}

	@Override
	public void init(H http) throws Exception {
		registerDefaultDeniedHandler(http);
		registerDefaultEntryPoint(http);
		registerDefaultCsrfOverride(http);
	}

	@Override
	public void configure(H http) throws Exception {
		BearerTokenResolver bearerTokenResolver = getBearerTokenResolver();
		this.requestMatcher.setBearerTokenResolver(bearerTokenResolver);

		AuthenticationManager manager = http.getSharedObject(AuthenticationManager.class);

		BearerTokenAuthenticationFilter filter =
				new BearerTokenAuthenticationFilter(manager);
		filter.setBearerTokenResolver(bearerTokenResolver);
		filter = postProcess(filter);

		http.addFilter(filter);

		if ( this.jwtConfigurer == null ) {
			throw new IllegalStateException("Jwt is the only supported format for bearer tokens " +
					"in Spring Security and no Jwt configuration was found. Make sure to specify " +
					"a jwk set uri by doing http.oauth2().resourceServer().jwt().jwkSetUri(uri), or wire a " +
					"JwtDecoder instance by doing http.oauth2().resourceServer().jwt().decoder(decoder), or " +
					"expose a JwtDecoder instance as a bean and do http.oauth2().resourceServer().jwt().");
		}

		JwtDecoder decoder = this.jwtConfigurer.getJwtDecoder();

		JwtAuthenticationProvider provider =
				new JwtAuthenticationProvider(decoder);
		provider = postProcess(provider);

		http.authenticationProvider(provider);
	}

	public class JwtConfigurer {
		private final ApplicationContext context;

		private JwtDecoder decoder;

		JwtConfigurer(ApplicationContext context) {
			this.context = context;
		}

		public OAuth2ResourceServerConfigurer<H> decoder(JwtDecoder decoder) {
			this.decoder = decoder;
			return OAuth2ResourceServerConfigurer.this;
		}

		public OAuth2ResourceServerConfigurer<H> jwkSetUri(String uri) {
			this.decoder = new NimbusJwtDecoderJwkSupport(uri);
			return OAuth2ResourceServerConfigurer.this;
		}

		JwtDecoder getJwtDecoder() {
			if ( this.decoder == null ) {
				return this.context.getBean(JwtDecoder.class);
			}

			return this.decoder;
		}
	}

	private void initSessionCreationPolicy(H http) {
		if (http.getSharedObject(SessionCreationPolicy.class) == null) {
			http.setSharedObject(SessionCreationPolicy.class, SessionCreationPolicy.STATELESS);
		}
	}

	private void registerDefaultDeniedHandler(H http) {
		ExceptionHandlingConfigurer<H> exceptionHandling = http
				.getConfigurer(ExceptionHandlingConfigurer.class);
		if (exceptionHandling == null) {
			return;
		}

		exceptionHandling.defaultAccessDeniedHandlerFor(
				this.accessDeniedHandler,
				this.requestMatcher);
	}

	private void registerDefaultEntryPoint(H http) {
		ExceptionHandlingConfigurer<H> exceptionHandling = http
				.getConfigurer(ExceptionHandlingConfigurer.class);
		if (exceptionHandling == null) {
			return;
		}

		exceptionHandling.defaultAuthenticationEntryPointFor(
				this.authenticationEntryPoint,
				this.requestMatcher);
	}

	private void registerDefaultCsrfOverride(H http) {
		CsrfConfigurer<H> csrf = http
				.getConfigurer(CsrfConfigurer.class);
		if (csrf == null) {
			return;
		}

		csrf.ignoringRequestMatchers(this.requestMatcher);
	}

	private BearerTokenResolver getBearerTokenResolver() {
		return this.bearerTokenResolver;
	}

	private static final class BearerTokenRequestMatcher implements RequestMatcher {
		private BearerTokenResolver bearerTokenResolver
				= new DefaultBearerTokenResolver();

		@Override
		public boolean matches(HttpServletRequest request) {
			return this.bearerTokenResolver.resolve(request) != null;
		}

		public void setBearerTokenResolver(BearerTokenResolver tokenResolver) {
			Assert.notNull(tokenResolver, "resolver cannot be null");
			this.bearerTokenResolver = tokenResolver;
		}
	}
}
