/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers.oauth2.server.resource;

import java.util.function.Supplier;
import javax.servlet.http.HttpServletRequest;

import org.springframework.context.ApplicationContext;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOAuth2TokenIntrospectionClient;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2TokenIntrospectionClient;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import static org.springframework.security.oauth2.jwt.NimbusJwtDecoder.withJwkSetUri;

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
 * <li>{@link #accessDeniedHandler(AccessDeniedHandler)}</li> - customizes how access denied errors are handled
 * <li>{@link #authenticationEntryPoint(AuthenticationEntryPoint)}</li> - customizes how authentication failures are handled
 * <li>{@link #bearerTokenResolver(BearerTokenResolver)} - customizes how to resolve a bearer token from the request</li>
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
 * Also with {@link #jwt()} consider
 *
 * <ul>
 * <li>
 * customizing the conversion from a {@link Jwt} to an {@link org.springframework.security.core.Authentication} with
 * {@link JwtConfigurer#jwtAuthenticationConverter(Converter)}
 * </li>
 * </ul>
 *
 * <p>
 * When using {@link #opaque()}, supply an introspection endpoint and its authentication configuration
 * </p>
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
 * @see NimbusJwtDecoder
 * @see AbstractHttpConfigurer
 */
public final class OAuth2ResourceServerConfigurer<H extends HttpSecurityBuilder<H>> extends
		AbstractHttpConfigurer<OAuth2ResourceServerConfigurer<H>, H> {

	private final ApplicationContext context;

	private AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver;
	private BearerTokenResolver bearerTokenResolver;

	private JwtConfigurer jwtConfigurer;
	private OpaqueTokenConfigurer opaqueTokenConfigurer;

	private AccessDeniedHandler accessDeniedHandler = new BearerTokenAccessDeniedHandler();
	private AuthenticationEntryPoint authenticationEntryPoint = new BearerTokenAuthenticationEntryPoint();
	private BearerTokenRequestMatcher requestMatcher = new BearerTokenRequestMatcher();

	public OAuth2ResourceServerConfigurer(ApplicationContext context) {
		Assert.notNull(context, "context cannot be null");
		this.context = context;
	}

	public OAuth2ResourceServerConfigurer<H> accessDeniedHandler(AccessDeniedHandler accessDeniedHandler) {
		Assert.notNull(accessDeniedHandler, "accessDeniedHandler cannot be null");
		this.accessDeniedHandler = accessDeniedHandler;
		return this;
	}

	public OAuth2ResourceServerConfigurer<H> authenticationEntryPoint(AuthenticationEntryPoint entryPoint) {
		Assert.notNull(entryPoint, "entryPoint cannot be null");
		this.authenticationEntryPoint = entryPoint;
		return this;
	}

	public OAuth2ResourceServerConfigurer<H> authenticationManagerResolver
			(AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver) {
		Assert.notNull(authenticationManagerResolver, "authenticationManagerResolver cannot be null");
		this.authenticationManagerResolver = authenticationManagerResolver;
		return this;
	}

	public OAuth2ResourceServerConfigurer<H> bearerTokenResolver(BearerTokenResolver bearerTokenResolver) {
		Assert.notNull(bearerTokenResolver, "bearerTokenResolver cannot be null");
		this.bearerTokenResolver = bearerTokenResolver;
		return this;
	}

	public JwtConfigurer jwt() {
		if ( this.jwtConfigurer == null ) {
			this.jwtConfigurer = new JwtConfigurer(this.context);
		}

		return this.jwtConfigurer;
	}

	public OpaqueTokenConfigurer opaqueToken() {
		if (this.opaqueTokenConfigurer == null) {
			this.opaqueTokenConfigurer = new OpaqueTokenConfigurer(this.context);
		}

		return this.opaqueTokenConfigurer;
	}

	@Override
	public void init(H http) throws Exception {
		registerDefaultAccessDeniedHandler(http);
		registerDefaultEntryPoint(http);
		registerDefaultCsrfOverride(http);
	}

	@Override
	public void configure(H http) throws Exception {
		BearerTokenResolver bearerTokenResolver = getBearerTokenResolver();
		this.requestMatcher.setBearerTokenResolver(bearerTokenResolver);

		AuthenticationManagerResolver resolver = this.authenticationManagerResolver;
		if (resolver == null) {
			resolver = request -> http.getSharedObject(AuthenticationManager.class);
		}

		BearerTokenAuthenticationFilter filter = new BearerTokenAuthenticationFilter(resolver);
		filter.setBearerTokenResolver(bearerTokenResolver);
		filter.setAuthenticationEntryPoint(this.authenticationEntryPoint);
		filter = postProcess(filter);

		http.addFilter(filter);

		if (this.jwtConfigurer != null && this.opaqueTokenConfigurer != null) {
			throw new IllegalStateException("Spring Security only supports JWTs or Opaque Tokens, not both at the " +
					"same time");
		}

		if (this.jwtConfigurer == null && this.opaqueTokenConfigurer == null &&
				this.authenticationManagerResolver == null ) {

			throw new IllegalStateException("Jwt and Opaque Token are the only supported formats for bearer tokens " +
					"in Spring Security and neither was found. Make sure to configure JWT " +
					"via http.oauth2ResourceServer().jwt() or Opaque Tokens via " +
					"http.oauth2ResourceServer().opaque().");
		}

		if (this.jwtConfigurer != null) {
			JwtDecoder decoder = this.jwtConfigurer.getJwtDecoder();
			Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter =
					this.jwtConfigurer.getJwtAuthenticationConverter();

			JwtAuthenticationProvider provider =
					new JwtAuthenticationProvider(decoder);
			provider.setJwtAuthenticationConverter(jwtAuthenticationConverter);
			provider = postProcess(provider);

			http.authenticationProvider(provider);
		}

		if (this.opaqueTokenConfigurer != null) {
			OAuth2TokenIntrospectionClient introspectionClient = this.opaqueTokenConfigurer.getIntrospectionClient();
			OAuth2IntrospectionAuthenticationProvider provider =
					new OAuth2IntrospectionAuthenticationProvider(introspectionClient);
			http.authenticationProvider(provider);
		}
	}

	public class JwtConfigurer {
		private final ApplicationContext context;

		private JwtDecoder decoder;

		private Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter =
				new JwtAuthenticationConverter();

		JwtConfigurer(ApplicationContext context) {
			this.context = context;
		}

		public JwtConfigurer decoder(JwtDecoder decoder) {
			this.decoder = decoder;
			return this;
		}

		public JwtConfigurer jwkSetUri(String uri) {
			this.decoder = withJwkSetUri(uri).build();
			return this;
		}

		public JwtConfigurer jwtAuthenticationConverter
				(Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter) {

			this.jwtAuthenticationConverter = jwtAuthenticationConverter;
			return this;
		}

		public OAuth2ResourceServerConfigurer<H> and() {
			return OAuth2ResourceServerConfigurer.this;
		}

		Converter<Jwt, ? extends AbstractAuthenticationToken> getJwtAuthenticationConverter() {
			return this.jwtAuthenticationConverter;
		}

		JwtDecoder getJwtDecoder() {
			if ( this.decoder == null ) {
				return this.context.getBean(JwtDecoder.class);
			}

			return this.decoder;
		}
	}

	public class OpaqueTokenConfigurer {
		private final ApplicationContext context;

		private String introspectionUri;
		private String clientId;
		private String clientSecret;
		private Supplier<OAuth2TokenIntrospectionClient> introspectionClient;

		OpaqueTokenConfigurer(ApplicationContext context) {
			this.context = context;
		}

		public OpaqueTokenConfigurer introspectionUri(String introspectionUri) {
			Assert.notNull(introspectionUri, "introspectionUri cannot be null");
			this.introspectionUri = introspectionUri;
			this.introspectionClient = () ->
					new NimbusOAuth2TokenIntrospectionClient(this.introspectionUri, this.clientId, this.clientSecret);
			return this;
		}

		public OpaqueTokenConfigurer introspectionClientCredentials(String clientId, String clientSecret) {
			Assert.notNull(clientId, "clientId cannot be null");
			Assert.notNull(clientSecret, "clientSecret cannot be null");
			this.clientId = clientId;
			this.clientSecret = clientSecret;
			this.introspectionClient = () ->
					new NimbusOAuth2TokenIntrospectionClient(this.introspectionUri, this.clientId, this.clientSecret);
			return this;
		}

		public OpaqueTokenConfigurer introspectionClient(OAuth2TokenIntrospectionClient introspectionClient) {
			Assert.notNull(introspectionClient, "introspectionClient cannot be null");
			this.introspectionClient = () -> introspectionClient;
			return this;
		}

		OAuth2TokenIntrospectionClient getIntrospectionClient() {
			if (this.introspectionClient != null) {
				return this.introspectionClient.get();
			}
			return this.context.getBean(OAuth2TokenIntrospectionClient.class);
		}
	}

	private void registerDefaultAccessDeniedHandler(H http) {
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

	BearerTokenResolver getBearerTokenResolver() {
		if ( this.bearerTokenResolver == null ) {
			if ( this.context.getBeanNamesForType(BearerTokenResolver.class).length > 0 ) {
				this.bearerTokenResolver = this.context.getBean(BearerTokenResolver.class);
			} else {
				this.bearerTokenResolver = new DefaultBearerTokenResolver();
			}
		}

		return this.bearerTokenResolver;
	}

	private static final class BearerTokenRequestMatcher implements RequestMatcher {
		private BearerTokenResolver bearerTokenResolver;

		@Override
		public boolean matches(HttpServletRequest request) {
			try {
				return this.bearerTokenResolver.resolve(request) != null;
			} catch ( OAuth2AuthenticationException e ) {
				return false;
			}
		}

		public void setBearerTokenResolver(BearerTokenResolver tokenResolver) {
			Assert.notNull(tokenResolver, "resolver cannot be null");
			this.bearerTokenResolver = tokenResolver;
		}
	}
}
