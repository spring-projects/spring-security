/*
 * Copyright 2002-2021 the original author or authors.
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

import java.util.Arrays;
import java.util.Collections;
import java.util.function.Supplier;

import javax.servlet.http.HttpServletRequest;

import org.springframework.context.ApplicationContext;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
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
import org.springframework.security.oauth2.server.resource.authentication.OpaqueTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

/**
 *
 * An {@link AbstractHttpConfigurer} for OAuth 2.0 Resource Server Support.
 *
 * By default, this wires a {@link BearerTokenAuthenticationFilter}, which can be used to
 * parse the request for bearer tokens and make an authentication attempt.
 *
 * <p>
 * The following configuration options are available:
 *
 * <ul>
 * <li>{@link #accessDeniedHandler(AccessDeniedHandler)}</li> - customizes how access
 * denied errors are handled
 * <li>{@link #authenticationEntryPoint(AuthenticationEntryPoint)}</li> - customizes how
 * authentication failures are handled
 * <li>{@link #bearerTokenResolver(BearerTokenResolver)} - customizes how to resolve a
 * bearer token from the request</li>
 * <li>{@link #jwt(Customizer)} - enables Jwt-encoded bearer token support</li>
 * <li>{@link #opaqueToken(Customizer)} - enables opaque bearer token support</li>
 * </ul>
 *
 * <p>
 * When using {@link #jwt(Customizer)}, either
 *
 * <ul>
 * <li>supply a Jwk Set Uri via {@link JwtConfigurer#jwkSetUri}, or</li>
 * <li>supply a {@link JwtDecoder} instance via {@link JwtConfigurer#decoder}, or</li>
 * <li>expose a {@link JwtDecoder} bean</li>
 * </ul>
 *
 * Also with {@link #jwt(Customizer)} consider
 *
 * <ul>
 * <li>customizing the conversion from a {@link Jwt} to an
 * {@link org.springframework.security.core.Authentication} with
 * {@link JwtConfigurer#jwtAuthenticationConverter(Converter)}</li>
 * </ul>
 *
 * <p>
 * When using {@link #opaqueToken(Customizer)}, supply an introspection endpoint and its
 * authentication configuration
 * </p>
 *
 * <h2>Security Filters</h2>
 *
 * The following {@code Filter}s are populated when {@link #jwt(Customizer)} is
 * configured:
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
 * @author Evgeniy Cheban
 * @since 5.1
 * @see BearerTokenAuthenticationFilter
 * @see JwtAuthenticationProvider
 * @see NimbusJwtDecoder
 * @see AbstractHttpConfigurer
 */
public final class OAuth2ResourceServerConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<OAuth2ResourceServerConfigurer<H>, H> {

	private static final RequestHeaderRequestMatcher X_REQUESTED_WITH = new RequestHeaderRequestMatcher(
			"X-Requested-With", "XMLHttpRequest");

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

	public OAuth2ResourceServerConfigurer<H> authenticationManagerResolver(
			AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver) {
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
		if (this.jwtConfigurer == null) {
			this.jwtConfigurer = new JwtConfigurer(this.context);
		}
		return this.jwtConfigurer;
	}

	/**
	 * Enables Jwt-encoded bearer token support.
	 * @param jwtCustomizer the {@link Customizer} to provide more options for the
	 * {@link JwtConfigurer}
	 * @return the {@link OAuth2ResourceServerConfigurer} for further customizations
	 */
	public OAuth2ResourceServerConfigurer<H> jwt(Customizer<JwtConfigurer> jwtCustomizer) {
		if (this.jwtConfigurer == null) {
			this.jwtConfigurer = new JwtConfigurer(this.context);
		}
		jwtCustomizer.customize(this.jwtConfigurer);
		return this;
	}

	public OpaqueTokenConfigurer opaqueToken() {
		if (this.opaqueTokenConfigurer == null) {
			this.opaqueTokenConfigurer = new OpaqueTokenConfigurer(this.context);
		}
		return this.opaqueTokenConfigurer;
	}

	/**
	 * Enables opaque bearer token support.
	 * @param opaqueTokenCustomizer the {@link Customizer} to provide more options for the
	 * {@link OpaqueTokenConfigurer}
	 * @return the {@link OAuth2ResourceServerConfigurer} for further customizations
	 */
	public OAuth2ResourceServerConfigurer<H> opaqueToken(Customizer<OpaqueTokenConfigurer> opaqueTokenCustomizer) {
		if (this.opaqueTokenConfigurer == null) {
			this.opaqueTokenConfigurer = new OpaqueTokenConfigurer(this.context);
		}
		opaqueTokenCustomizer.customize(this.opaqueTokenConfigurer);
		return this;
	}

	@Override
	public void init(H http) {
		validateConfiguration();
		registerDefaultAccessDeniedHandler(http);
		registerDefaultEntryPoint(http);
		registerDefaultCsrfOverride(http);
		AuthenticationProvider authenticationProvider = getAuthenticationProvider();
		if (authenticationProvider != null) {
			http.authenticationProvider(authenticationProvider);
		}
	}

	@Override
	public void configure(H http) {
		BearerTokenResolver bearerTokenResolver = getBearerTokenResolver();
		this.requestMatcher.setBearerTokenResolver(bearerTokenResolver);
		AuthenticationManagerResolver resolver = this.authenticationManagerResolver;
		if (resolver == null) {
			AuthenticationManager authenticationManager = getAuthenticationManager(http);
			resolver = (request) -> authenticationManager;
		}

		BearerTokenAuthenticationFilter filter = new BearerTokenAuthenticationFilter(resolver);
		filter.setBearerTokenResolver(bearerTokenResolver);
		filter.setAuthenticationEntryPoint(this.authenticationEntryPoint);
		filter = postProcess(filter);
		http.addFilter(filter);
	}

	private void validateConfiguration() {
		if (this.authenticationManagerResolver == null) {
			Assert.state(this.jwtConfigurer != null || this.opaqueTokenConfigurer != null,
					"Jwt and Opaque Token are the only supported formats for bearer tokens "
							+ "in Spring Security and neither was found. Make sure to configure JWT "
							+ "via http.oauth2ResourceServer().jwt() or Opaque Tokens via "
							+ "http.oauth2ResourceServer().opaqueToken().");
			Assert.state(this.jwtConfigurer == null || this.opaqueTokenConfigurer == null,
					"Spring Security only supports JWTs or Opaque Tokens, not both at the " + "same time.");
		}
		else {
			Assert.state(this.jwtConfigurer == null && this.opaqueTokenConfigurer == null,
					"If an authenticationManagerResolver() is configured, then it takes "
							+ "precedence over any jwt() or opaqueToken() configuration.");
		}
	}

	private void registerDefaultAccessDeniedHandler(H http) {
		ExceptionHandlingConfigurer<H> exceptionHandling = http.getConfigurer(ExceptionHandlingConfigurer.class);
		if (exceptionHandling != null) {
			exceptionHandling.defaultAccessDeniedHandlerFor(this.accessDeniedHandler, this.requestMatcher);
		}
	}

	private void registerDefaultEntryPoint(H http) {
		ExceptionHandlingConfigurer<H> exceptionHandling = http.getConfigurer(ExceptionHandlingConfigurer.class);
		if (exceptionHandling != null) {
			ContentNegotiationStrategy contentNegotiationStrategy = http
					.getSharedObject(ContentNegotiationStrategy.class);
			if (contentNegotiationStrategy == null) {
				contentNegotiationStrategy = new HeaderContentNegotiationStrategy();
			}
			MediaTypeRequestMatcher restMatcher = new MediaTypeRequestMatcher(contentNegotiationStrategy,
					MediaType.APPLICATION_ATOM_XML, MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON,
					MediaType.APPLICATION_OCTET_STREAM, MediaType.APPLICATION_XML, MediaType.MULTIPART_FORM_DATA,
					MediaType.TEXT_XML);
			restMatcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
			MediaTypeRequestMatcher allMatcher = new MediaTypeRequestMatcher(contentNegotiationStrategy, MediaType.ALL);
			allMatcher.setUseEquals(true);
			RequestMatcher notHtmlMatcher = new NegatedRequestMatcher(
					new MediaTypeRequestMatcher(contentNegotiationStrategy, MediaType.TEXT_HTML));
			RequestMatcher restNotHtmlMatcher = new AndRequestMatcher(
					Arrays.<RequestMatcher>asList(notHtmlMatcher, restMatcher));
			RequestMatcher preferredMatcher = new OrRequestMatcher(
					Arrays.asList(this.requestMatcher, X_REQUESTED_WITH, restNotHtmlMatcher, allMatcher));
			exceptionHandling.defaultAuthenticationEntryPointFor(this.authenticationEntryPoint, preferredMatcher);
		}
	}

	private void registerDefaultCsrfOverride(H http) {
		CsrfConfigurer<H> csrf = http.getConfigurer(CsrfConfigurer.class);
		if (csrf != null) {
			csrf.ignoringRequestMatchers(this.requestMatcher);
		}
	}

	AuthenticationProvider getAuthenticationProvider() {
		if (this.jwtConfigurer != null) {
			return this.jwtConfigurer.getAuthenticationProvider();
		}
		if (this.opaqueTokenConfigurer != null) {
			return this.opaqueTokenConfigurer.getAuthenticationProvider();
		}
		return null;
	}

	AuthenticationManager getAuthenticationManager(H http) {
		if (this.jwtConfigurer != null) {
			return this.jwtConfigurer.getAuthenticationManager(http);
		}
		if (this.opaqueTokenConfigurer != null) {
			return this.opaqueTokenConfigurer.getAuthenticationManager(http);
		}
		return http.getSharedObject(AuthenticationManager.class);
	}

	BearerTokenResolver getBearerTokenResolver() {
		if (this.bearerTokenResolver == null) {
			if (this.context.getBeanNamesForType(BearerTokenResolver.class).length > 0) {
				this.bearerTokenResolver = this.context.getBean(BearerTokenResolver.class);
			}
			else {
				this.bearerTokenResolver = new DefaultBearerTokenResolver();
			}
		}
		return this.bearerTokenResolver;
	}

	public class JwtConfigurer {

		private final ApplicationContext context;

		private AuthenticationManager authenticationManager;

		private JwtDecoder decoder;

		private Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter;

		JwtConfigurer(ApplicationContext context) {
			this.context = context;
		}

		public JwtConfigurer authenticationManager(AuthenticationManager authenticationManager) {
			Assert.notNull(authenticationManager, "authenticationManager cannot be null");
			this.authenticationManager = authenticationManager;
			return this;
		}

		public JwtConfigurer decoder(JwtDecoder decoder) {
			this.decoder = decoder;
			return this;
		}

		public JwtConfigurer jwkSetUri(String uri) {
			this.decoder = NimbusJwtDecoder.withJwkSetUri(uri).build();
			return this;
		}

		public JwtConfigurer jwtAuthenticationConverter(
				Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter) {
			this.jwtAuthenticationConverter = jwtAuthenticationConverter;
			return this;
		}

		public OAuth2ResourceServerConfigurer<H> and() {
			return OAuth2ResourceServerConfigurer.this;
		}

		Converter<Jwt, ? extends AbstractAuthenticationToken> getJwtAuthenticationConverter() {
			if (this.jwtAuthenticationConverter == null) {
				if (this.context.getBeanNamesForType(JwtAuthenticationConverter.class).length > 0) {
					this.jwtAuthenticationConverter = this.context.getBean(JwtAuthenticationConverter.class);
				}
				else {
					this.jwtAuthenticationConverter = new JwtAuthenticationConverter();
				}
			}
			return this.jwtAuthenticationConverter;
		}

		JwtDecoder getJwtDecoder() {
			if (this.decoder == null) {
				return this.context.getBean(JwtDecoder.class);
			}
			return this.decoder;
		}

		AuthenticationProvider getAuthenticationProvider() {
			if (this.authenticationManager != null) {
				return null;
			}
			JwtDecoder decoder = getJwtDecoder();
			Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter = getJwtAuthenticationConverter();
			JwtAuthenticationProvider provider = new JwtAuthenticationProvider(decoder);
			provider.setJwtAuthenticationConverter(jwtAuthenticationConverter);
			return postProcess(provider);
		}

		AuthenticationManager getAuthenticationManager(H http) {
			if (this.authenticationManager != null) {
				return this.authenticationManager;
			}
			return http.getSharedObject(AuthenticationManager.class);
		}

	}

	public class OpaqueTokenConfigurer {

		private final ApplicationContext context;

		private AuthenticationManager authenticationManager;

		private String introspectionUri;

		private String clientId;

		private String clientSecret;

		private Supplier<OpaqueTokenIntrospector> introspector;

		OpaqueTokenConfigurer(ApplicationContext context) {
			this.context = context;
		}

		public OpaqueTokenConfigurer authenticationManager(AuthenticationManager authenticationManager) {
			Assert.notNull(authenticationManager, "authenticationManager cannot be null");
			this.authenticationManager = authenticationManager;
			return this;
		}

		public OpaqueTokenConfigurer introspectionUri(String introspectionUri) {
			Assert.notNull(introspectionUri, "introspectionUri cannot be null");
			this.introspectionUri = introspectionUri;
			this.introspector = () -> new NimbusOpaqueTokenIntrospector(this.introspectionUri, this.clientId,
					this.clientSecret);
			return this;
		}

		public OpaqueTokenConfigurer introspectionClientCredentials(String clientId, String clientSecret) {
			Assert.notNull(clientId, "clientId cannot be null");
			Assert.notNull(clientSecret, "clientSecret cannot be null");
			this.clientId = clientId;
			this.clientSecret = clientSecret;
			this.introspector = () -> new NimbusOpaqueTokenIntrospector(this.introspectionUri, this.clientId,
					this.clientSecret);
			return this;
		}

		public OpaqueTokenConfigurer introspector(OpaqueTokenIntrospector introspector) {
			Assert.notNull(introspector, "introspector cannot be null");
			this.introspector = () -> introspector;
			return this;
		}

		OpaqueTokenIntrospector getIntrospector() {
			if (this.introspector != null) {
				return this.introspector.get();
			}
			return this.context.getBean(OpaqueTokenIntrospector.class);
		}

		AuthenticationProvider getAuthenticationProvider() {
			if (this.authenticationManager != null) {
				return null;
			}
			OpaqueTokenIntrospector introspector = getIntrospector();
			return new OpaqueTokenAuthenticationProvider(introspector);
		}

		AuthenticationManager getAuthenticationManager(H http) {
			if (this.authenticationManager != null) {
				return this.authenticationManager;
			}
			return http.getSharedObject(AuthenticationManager.class);
		}

	}

	private static final class BearerTokenRequestMatcher implements RequestMatcher {

		private BearerTokenResolver bearerTokenResolver;

		@Override
		public boolean matches(HttpServletRequest request) {
			try {
				return this.bearerTokenResolver.resolve(request) != null;
			}
			catch (OAuth2AuthenticationException ex) {
				return false;
			}
		}

		void setBearerTokenResolver(BearerTokenResolver tokenResolver) {
			Assert.notNull(tokenResolver, "resolver cannot be null");
			this.bearerTokenResolver = tokenResolver;
		}

	}

}
