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

package org.springframework.security.test.web.reactive.server;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import com.nimbusds.oauth2.sdk.util.StringUtils;
import reactor.core.publisher.Mono;

import org.springframework.context.ApplicationContext;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.reactive.result.method.annotation.OAuth2AuthorizedClientArgumentResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.WebSessionServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.security.web.server.csrf.CsrfWebFilter;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.reactive.server.MockServerConfigurer;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.test.web.reactive.server.WebTestClientConfigurer;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.web.reactive.result.method.HandlerMethodArgumentResolver;
import org.springframework.web.reactive.result.method.annotation.ArgumentResolverConfigurer;
import org.springframework.web.reactive.result.method.annotation.RequestMappingHandlerAdapter;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.server.adapter.WebHttpHandlerBuilder;

import static java.lang.Boolean.TRUE;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.SUB;

/**
 * Test utilities for working with Spring Security and
 * {@link org.springframework.test.web.reactive.server.WebTestClient.Builder#apply(WebTestClientConfigurer)}.
 *
 * @author Rob Winch
 * @since 5.0
 */
public class SecurityMockServerConfigurers {

	/**
	 * Sets up Spring Security's {@link WebTestClient} test support
	 * @return the MockServerConfigurer to use
	 */
	public static MockServerConfigurer springSecurity() {
		return new MockServerConfigurer() {
			@Override
			public void beforeServerCreated(WebHttpHandlerBuilder builder) {
				builder.filters(filters -> filters.add(0, new MutatorFilter()));
			}
		};
	}

	/**
	 * Updates the ServerWebExchange to use the provided Authentication as the Principal
	 * @param authentication the Authentication to use.
	 * @return the configurer to use
	 */
	public static <T extends WebTestClientConfigurer & MockServerConfigurer> T mockAuthentication(
			Authentication authentication) {
		return (T) new MutatorWebTestClientConfigurer(() -> Mono.just(authentication).map(SecurityContextImpl::new));
	}

	/**
	 * Updates the ServerWebExchange to use the provided UserDetails to create a
	 * UsernamePasswordAuthenticationToken as the Principal
	 * @param userDetails the UserDetails to use.
	 * @return the configurer to use
	 */
	public static <T extends WebTestClientConfigurer & MockServerConfigurer> T mockUser(UserDetails userDetails) {
		return mockAuthentication(new UsernamePasswordAuthenticationToken(userDetails, userDetails.getPassword(),
				userDetails.getAuthorities()));
	}

	/**
	 * Updates the ServerWebExchange to use a UserDetails to create a
	 * UsernamePasswordAuthenticationToken as the Principal. This uses a default username
	 * of "user", password of "password", and granted authorities of "ROLE_USER".
	 * @return the {@link UserExchangeMutator} to use
	 */
	public static UserExchangeMutator mockUser() {
		return mockUser("user");
	}

	/**
	 * Updates the ServerWebExchange to use a UserDetails to create a
	 * UsernamePasswordAuthenticationToken as the Principal. This uses a default password
	 * of "password" and granted authorities of "ROLE_USER".
	 * @return the {@link WebTestClientConfigurer} to use
	 */
	public static UserExchangeMutator mockUser(String username) {
		return new UserExchangeMutator(username);
	}

	/**
	 * Updates the ServerWebExchange to establish a {@link SecurityContext} that has a
	 * {@link JwtAuthenticationToken} for the {@link Authentication} and a {@link Jwt} for
	 * the {@link Authentication#getPrincipal()}. All details are declarative and do not
	 * require the JWT to be valid.
	 * @return the {@link JwtMutator} to further configure or use
	 * @since 5.2
	 */
	public static JwtMutator mockJwt() {
		return new JwtMutator();
	}

	/**
	 * Updates the ServerWebExchange to establish a {@link SecurityContext} that has a
	 * {@link BearerTokenAuthentication} for the {@link Authentication} and an
	 * {@link OAuth2AuthenticatedPrincipal} for the {@link Authentication#getPrincipal()}.
	 * All details are declarative and do not require the token to be valid.
	 * @return the {@link OpaqueTokenMutator} to further configure or use
	 * @since 5.3
	 */
	public static OpaqueTokenMutator mockOpaqueToken() {
		return new OpaqueTokenMutator();
	}

	/**
	 * Updates the ServerWebExchange to establish a {@link SecurityContext} that has a
	 * {@link OAuth2AuthenticationToken} for the {@link Authentication}. All details are
	 * declarative and do not require the corresponding OAuth 2.0 tokens to be valid.
	 * @return the {@link OAuth2LoginMutator} to further configure or use
	 * @since 5.3
	 */
	public static OAuth2LoginMutator mockOAuth2Login() {
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-token", null,
				null, Collections.singleton("read"));
		return new OAuth2LoginMutator(accessToken);
	}

	/**
	 * Updates the ServerWebExchange to establish a {@link SecurityContext} that has a
	 * {@link OAuth2AuthenticationToken} for the {@link Authentication}. All details are
	 * declarative and do not require the corresponding OAuth 2.0 tokens to be valid.
	 * @return the {@link OidcLoginMutator} to further configure or use
	 * @since 5.3
	 */
	public static OidcLoginMutator mockOidcLogin() {
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-token", null,
				null, Collections.singleton("read"));
		return new OidcLoginMutator(accessToken);
	}

	/**
	 * Updates the ServerWebExchange to establish a {@link OAuth2AuthorizedClient} in the
	 * session. All details are declarative and do not require the corresponding OAuth 2.0
	 * tokens to be valid.
	 *
	 * <p>
	 * The support works by associating the authorized client to the ServerWebExchange via
	 * the {@link WebSessionServerOAuth2AuthorizedClientRepository}
	 * </p>
	 * @return the {@link OAuth2ClientMutator} to further configure or use
	 * @since 5.3
	 */
	public static OAuth2ClientMutator mockOAuth2Client() {
		return new OAuth2ClientMutator();
	}

	/**
	 * Updates the ServerWebExchange to establish a {@link OAuth2AuthorizedClient} in the
	 * session. All details are declarative and do not require the corresponding OAuth 2.0
	 * tokens to be valid.
	 *
	 * <p>
	 * The support works by associating the authorized client to the ServerWebExchange via
	 * the {@link WebSessionServerOAuth2AuthorizedClientRepository}
	 * </p>
	 * @param registrationId The registration id associated with the
	 * {@link OAuth2AuthorizedClient}
	 * @return the {@link OAuth2ClientMutator} to further configure or use
	 * @since 5.3
	 */
	public static OAuth2ClientMutator mockOAuth2Client(String registrationId) {
		return new OAuth2ClientMutator(registrationId);
	}

	public static CsrfMutator csrf() {
		return new CsrfMutator();
	}

	public static final class CsrfMutator implements WebTestClientConfigurer, MockServerConfigurer {

		private CsrfMutator() {
		}

		@Override
		public void afterConfigurerAdded(WebTestClient.Builder builder,
				@Nullable WebHttpHandlerBuilder httpHandlerBuilder, @Nullable ClientHttpConnector connector) {
			CsrfWebFilter filter = new CsrfWebFilter();
			filter.setRequireCsrfProtectionMatcher(e -> ServerWebExchangeMatcher.MatchResult.notMatch());
			httpHandlerBuilder.filters(filters -> filters.add(0, filter));
		}

		@Override
		public void afterConfigureAdded(WebTestClient.MockServerSpec<?> serverSpec) {

		}

		@Override
		public void beforeServerCreated(WebHttpHandlerBuilder builder) {

		}

	}

	/**
	 * Updates the WebServerExchange using {@code {@link
	 * SecurityMockServerConfigurers#mockUser(UserDetails)}}. Defaults to use a password
	 * of "password" and granted authorities of "ROLE_USER".
	 */
	public static final class UserExchangeMutator implements WebTestClientConfigurer, MockServerConfigurer {

		private final User.UserBuilder userBuilder;

		private UserExchangeMutator(String username) {
			this.userBuilder = User.withUsername(username);
			password("password");
			roles("USER");
		}

		/**
		 * Specifies the password to use. Default is "password".
		 * @param password the password to use
		 * @return the UserExchangeMutator
		 */
		public UserExchangeMutator password(String password) {
			this.userBuilder.password(password);
			return this;
		}

		/**
		 * Specifies the roles to use. Default is "USER". This is similar to authorities
		 * except each role is automatically prefixed with "ROLE_USER".
		 * @param roles the roles to use.
		 * @return the UserExchangeMutator
		 */
		public UserExchangeMutator roles(String... roles) {
			this.userBuilder.roles(roles);
			return this;
		}

		/**
		 * Specifies the {@code GrantedAuthority}s to use. Default is "ROLE_USER".
		 * @param authorities the authorities to use.
		 * @return the UserExchangeMutator
		 */
		public UserExchangeMutator authorities(GrantedAuthority... authorities) {
			this.userBuilder.authorities(authorities);
			return this;
		}

		/**
		 * Specifies the {@code GrantedAuthority}s to use. Default is "ROLE_USER".
		 * @param authorities the authorities to use.
		 * @return the UserExchangeMutator
		 */
		public UserExchangeMutator authorities(Collection<? extends GrantedAuthority> authorities) {
			this.userBuilder.authorities(authorities);
			return this;
		}

		/**
		 * Specifies the {@code GrantedAuthority}s to use. Default is "ROLE_USER".
		 * @param authorities the authorities to use.
		 * @return the UserExchangeMutator
		 */
		public UserExchangeMutator authorities(String... authorities) {
			this.userBuilder.authorities(authorities);
			return this;
		}

		public UserExchangeMutator accountExpired(boolean accountExpired) {
			this.userBuilder.accountExpired(accountExpired);
			return this;
		}

		public UserExchangeMutator accountLocked(boolean accountLocked) {
			this.userBuilder.accountLocked(accountLocked);
			return this;
		}

		public UserExchangeMutator credentialsExpired(boolean credentialsExpired) {
			this.userBuilder.credentialsExpired(credentialsExpired);
			return this;
		}

		public UserExchangeMutator disabled(boolean disabled) {
			this.userBuilder.disabled(disabled);
			return this;
		}

		@Override
		public void beforeServerCreated(WebHttpHandlerBuilder builder) {
			configurer().beforeServerCreated(builder);
		}

		@Override
		public void afterConfigureAdded(WebTestClient.MockServerSpec<?> serverSpec) {
			configurer().afterConfigureAdded(serverSpec);
		}

		@Override
		public void afterConfigurerAdded(WebTestClient.Builder builder,
				@Nullable WebHttpHandlerBuilder webHttpHandlerBuilder,
				@Nullable ClientHttpConnector clientHttpConnector) {
			configurer().afterConfigurerAdded(builder, webHttpHandlerBuilder, clientHttpConnector);
		}

		private <T extends WebTestClientConfigurer & MockServerConfigurer> T configurer() {
			return mockUser(this.userBuilder.build());
		}

	}

	private static final class MutatorWebTestClientConfigurer implements WebTestClientConfigurer, MockServerConfigurer {

		private final Supplier<Mono<SecurityContext>> context;

		private MutatorWebTestClientConfigurer(Supplier<Mono<SecurityContext>> context) {
			this.context = context;
		}

		@Override
		public void beforeServerCreated(WebHttpHandlerBuilder builder) {
			builder.filters(addSetupMutatorFilter());
		}

		@Override
		public void afterConfigurerAdded(WebTestClient.Builder builder,
				@Nullable WebHttpHandlerBuilder webHttpHandlerBuilder,
				@Nullable ClientHttpConnector clientHttpConnector) {
			webHttpHandlerBuilder.filters(addSetupMutatorFilter());
		}

		private Consumer<List<WebFilter>> addSetupMutatorFilter() {
			return filters -> filters.add(0, new SetupMutatorFilter(this.context));
		}

	}

	private static final class SetupMutatorFilter implements WebFilter {

		private final Supplier<Mono<SecurityContext>> context;

		private SetupMutatorFilter(Supplier<Mono<SecurityContext>> context) {
			this.context = context;
		}

		@Override
		public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain webFilterChain) {
			exchange.getAttributes().computeIfAbsent(MutatorFilter.ATTRIBUTE_NAME, key -> this.context);
			return webFilterChain.filter(exchange);
		}

	}

	private static class MutatorFilter implements WebFilter {

		public static final String ATTRIBUTE_NAME = "context";

		@Override
		public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain webFilterChain) {
			Supplier<Mono<SecurityContext>> context = exchange.getAttribute(ATTRIBUTE_NAME);
			if (context != null) {
				exchange.getAttributes().remove(ATTRIBUTE_NAME);
				return webFilterChain.filter(exchange)
						.subscriberContext(ReactiveSecurityContextHolder.withSecurityContext(context.get()));
			}
			return webFilterChain.filter(exchange);
		}

	}

	/**
	 * Updates the WebServerExchange using {@code {@link
	 * SecurityMockServerConfigurers#mockAuthentication(Authentication)}}.
	 *
	 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
	 * @author Josh Cummings
	 * @since 5.2
	 */
	public static final class JwtMutator implements WebTestClientConfigurer, MockServerConfigurer {

		private Jwt jwt;

		private Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter = new JwtGrantedAuthoritiesConverter();

		private JwtMutator() {
			jwt((jwt) -> {
			});
		}

		/**
		 * Use the given {@link Jwt.Builder} {@link Consumer} to configure the underlying
		 * {@link Jwt}
		 *
		 * This method first creates a default {@link Jwt.Builder} instance with default
		 * values for the {@code alg}, {@code sub}, and {@code scope} claims. The
		 * {@link Consumer} can then modify these or provide additional configuration.
		 *
		 * Calling {@link SecurityMockServerConfigurers#mockJwt()} is the equivalent of
		 * calling {@code SecurityMockMvcRequestPostProcessors.mockJwt().jwt(() -> {})}.
		 * @param jwtBuilderConsumer For configuring the underlying {@link Jwt}
		 * @return the {@link JwtMutator} for further configuration
		 */
		public JwtMutator jwt(Consumer<Jwt.Builder> jwtBuilderConsumer) {
			Jwt.Builder jwtBuilder = Jwt.withTokenValue("token").header("alg", "none").claim(SUB, "user").claim("scope",
					"read");
			jwtBuilderConsumer.accept(jwtBuilder);
			this.jwt = jwtBuilder.build();
			return this;
		}

		/**
		 * Use the given {@link Jwt}
		 * @param jwt The {@link Jwt} to use
		 * @return the {@link JwtMutator} for further configuration
		 */
		public JwtMutator jwt(Jwt jwt) {
			this.jwt = jwt;
			return this;
		}

		/**
		 * Use the provided authorities in the token
		 * @param authorities the authorities to use
		 * @return the {@link JwtMutator} for further configuration
		 */
		public JwtMutator authorities(Collection<GrantedAuthority> authorities) {
			Assert.notNull(authorities, "authorities cannot be null");
			this.authoritiesConverter = jwt -> authorities;
			return this;
		}

		/**
		 * Use the provided authorities in the token
		 * @param authorities the authorities to use
		 * @return the {@link JwtMutator} for further configuration
		 */
		public JwtMutator authorities(GrantedAuthority... authorities) {
			Assert.notNull(authorities, "authorities cannot be null");
			this.authoritiesConverter = jwt -> Arrays.asList(authorities);
			return this;
		}

		/**
		 * Provides the configured {@link Jwt} so that custom authorities can be derived
		 * from it
		 * @param authoritiesConverter the conversion strategy from {@link Jwt} to a
		 * {@link Collection} of {@link GrantedAuthority}s
		 * @return the {@link JwtMutator} for further configuration
		 */
		public JwtMutator authorities(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
			Assert.notNull(authoritiesConverter, "authoritiesConverter cannot be null");
			this.authoritiesConverter = authoritiesConverter;
			return this;
		}

		@Override
		public void beforeServerCreated(WebHttpHandlerBuilder builder) {
			configurer().beforeServerCreated(builder);
		}

		@Override
		public void afterConfigureAdded(WebTestClient.MockServerSpec<?> serverSpec) {
			configurer().afterConfigureAdded(serverSpec);
		}

		@Override
		public void afterConfigurerAdded(WebTestClient.Builder builder,
				@Nullable WebHttpHandlerBuilder httpHandlerBuilder, @Nullable ClientHttpConnector connector) {
			httpHandlerBuilder.filter((exchange, chain) -> {
				CsrfWebFilter.skipExchange(exchange);
				return chain.filter(exchange);
			});
			configurer().afterConfigurerAdded(builder, httpHandlerBuilder, connector);
		}

		private <T extends WebTestClientConfigurer & MockServerConfigurer> T configurer() {
			return mockAuthentication(
					new JwtAuthenticationToken(this.jwt, this.authoritiesConverter.convert(this.jwt)));
		}

	}

	/**
	 * @author Josh Cummings
	 * @since 5.3
	 */
	public final static class OpaqueTokenMutator implements WebTestClientConfigurer, MockServerConfigurer {

		private Supplier<Map<String, Object>> attributes = this::defaultAttributes;

		private Supplier<Collection<GrantedAuthority>> authorities = this::defaultAuthorities;

		private Supplier<OAuth2AuthenticatedPrincipal> principal = this::defaultPrincipal;

		private OpaqueTokenMutator() {
		}

		/**
		 * Mutate the attributes using the given {@link Consumer}
		 * @param attributesConsumer The {@link Consumer} for mutating the {@Map} of
		 * attributes
		 * @return the {@link OpaqueTokenMutator} for further configuration
		 */
		public OpaqueTokenMutator attributes(Consumer<Map<String, Object>> attributesConsumer) {
			Assert.notNull(attributesConsumer, "attributesConsumer cannot be null");
			this.attributes = () -> {
				Map<String, Object> attributes = defaultAttributes();
				attributesConsumer.accept(attributes);
				return attributes;
			};
			this.principal = this::defaultPrincipal;
			return this;
		}

		/**
		 * Use the provided authorities in the resulting principal
		 * @param authorities the authorities to use
		 * @return the {@link OpaqueTokenMutator} for further configuration
		 */
		public OpaqueTokenMutator authorities(Collection<GrantedAuthority> authorities) {
			Assert.notNull(authorities, "authorities cannot be null");
			this.authorities = () -> authorities;
			this.principal = this::defaultPrincipal;
			return this;
		}

		/**
		 * Use the provided authorities in the resulting principal
		 * @param authorities the authorities to use
		 * @return the {@link OpaqueTokenMutator} for further configuration
		 */
		public OpaqueTokenMutator authorities(GrantedAuthority... authorities) {
			Assert.notNull(authorities, "authorities cannot be null");
			this.authorities = () -> Arrays.asList(authorities);
			this.principal = this::defaultPrincipal;
			return this;
		}

		/**
		 * Use the provided principal
		 * @param principal the principal to use
		 * @return the {@link OpaqueTokenMutator} for further configuration
		 */
		public OpaqueTokenMutator principal(OAuth2AuthenticatedPrincipal principal) {
			Assert.notNull(principal, "principal cannot be null");
			this.principal = () -> principal;
			return this;
		}

		@Override
		public void beforeServerCreated(WebHttpHandlerBuilder builder) {
			configurer().beforeServerCreated(builder);
		}

		@Override
		public void afterConfigureAdded(WebTestClient.MockServerSpec<?> serverSpec) {
			configurer().afterConfigureAdded(serverSpec);
		}

		@Override
		public void afterConfigurerAdded(WebTestClient.Builder builder,
				@Nullable WebHttpHandlerBuilder httpHandlerBuilder, @Nullable ClientHttpConnector connector) {
			httpHandlerBuilder.filter((exchange, chain) -> {
				CsrfWebFilter.skipExchange(exchange);
				return chain.filter(exchange);
			});
			configurer().afterConfigurerAdded(builder, httpHandlerBuilder, connector);
		}

		private <T extends WebTestClientConfigurer & MockServerConfigurer> T configurer() {
			OAuth2AuthenticatedPrincipal principal = this.principal.get();
			OAuth2AccessToken accessToken = getOAuth2AccessToken(principal);
			BearerTokenAuthentication token = new BearerTokenAuthentication(principal, accessToken,
					principal.getAuthorities());
			return mockAuthentication(token);
		}

		private Map<String, Object> defaultAttributes() {
			Map<String, Object> attributes = new HashMap<>();
			attributes.put(OAuth2IntrospectionClaimNames.SUBJECT, "user");
			attributes.put(OAuth2IntrospectionClaimNames.SCOPE, "read");
			return attributes;
		}

		private Collection<GrantedAuthority> defaultAuthorities() {
			Map<String, Object> attributes = this.attributes.get();
			Object scope = attributes.get(OAuth2IntrospectionClaimNames.SCOPE);
			if (scope == null) {
				return Collections.emptyList();
			}
			if (scope instanceof Collection) {
				return getAuthorities((Collection) scope);
			}
			String scopes = scope.toString();
			if (StringUtils.isBlank(scopes)) {
				return Collections.emptyList();
			}
			return getAuthorities(Arrays.asList(scopes.split(" ")));
		}

		private OAuth2AuthenticatedPrincipal defaultPrincipal() {
			return new OAuth2IntrospectionAuthenticatedPrincipal(this.attributes.get(), this.authorities.get());
		}

		private Collection<GrantedAuthority> getAuthorities(Collection<?> scopes) {
			return scopes.stream().map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
					.collect(Collectors.toList());
		}

		private OAuth2AccessToken getOAuth2AccessToken(OAuth2AuthenticatedPrincipal principal) {
			Instant expiresAt = getInstant(principal.getAttributes(), "exp");
			Instant issuedAt = getInstant(principal.getAttributes(), "iat");
			return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "token", issuedAt, expiresAt);
		}

		private Instant getInstant(Map<String, Object> attributes, String name) {
			Object value = attributes.get(name);
			if (value == null) {
				return null;
			}
			if (value instanceof Instant) {
				return (Instant) value;
			}
			throw new IllegalArgumentException(name + " attribute must be of type Instant");
		}

	}

	/**
	 * @author Josh Cummings
	 * @since 5.3
	 */
	public final static class OAuth2LoginMutator implements WebTestClientConfigurer, MockServerConfigurer {

		private final String nameAttributeKey = "sub";

		private ClientRegistration clientRegistration;

		private OAuth2AccessToken accessToken;

		private Supplier<Collection<GrantedAuthority>> authorities = this::defaultAuthorities;

		private Supplier<Map<String, Object>> attributes = this::defaultAttributes;

		private Supplier<OAuth2User> oauth2User = this::defaultPrincipal;

		private final ServerOAuth2AuthorizedClientRepository authorizedClientRepository = new WebSessionServerOAuth2AuthorizedClientRepository();

		private OAuth2LoginMutator(OAuth2AccessToken accessToken) {
			this.accessToken = accessToken;
			this.clientRegistration = clientRegistrationBuilder().build();
		}

		/**
		 * Use the provided authorities in the {@link Authentication}
		 * @param authorities the authorities to use
		 * @return the {@link OAuth2LoginMutator} for further configuration
		 */
		public OAuth2LoginMutator authorities(Collection<GrantedAuthority> authorities) {
			Assert.notNull(authorities, "authorities cannot be null");
			this.authorities = () -> authorities;
			this.oauth2User = this::defaultPrincipal;
			return this;
		}

		/**
		 * Use the provided authorities in the {@link Authentication}
		 * @param authorities the authorities to use
		 * @return the {@link OAuth2LoginMutator} for further configuration
		 */
		public OAuth2LoginMutator authorities(GrantedAuthority... authorities) {
			Assert.notNull(authorities, "authorities cannot be null");
			this.authorities = () -> Arrays.asList(authorities);
			this.oauth2User = this::defaultPrincipal;
			return this;
		}

		/**
		 * Mutate the attributes using the given {@link Consumer}
		 * @param attributesConsumer The {@link Consumer} for mutating the {@Map} of
		 * attributes
		 * @return the {@link OAuth2LoginMutator} for further configuration
		 */
		public OAuth2LoginMutator attributes(Consumer<Map<String, Object>> attributesConsumer) {
			Assert.notNull(attributesConsumer, "attributesConsumer cannot be null");
			this.attributes = () -> {
				Map<String, Object> attributes = defaultAttributes();
				attributesConsumer.accept(attributes);
				return attributes;
			};
			this.oauth2User = this::defaultPrincipal;
			return this;
		}

		/**
		 * Use the provided {@link OAuth2User} as the authenticated user.
		 * @param oauth2User the {@link OAuth2User} to use
		 * @return the {@link OAuth2LoginMutator} for further configuration
		 */
		public OAuth2LoginMutator oauth2User(OAuth2User oauth2User) {
			this.oauth2User = () -> oauth2User;
			return this;
		}

		/**
		 * Use the provided {@link ClientRegistration} as the client to authorize.
		 * <p>
		 * The supplied {@link ClientRegistration} will be registered into an
		 * {@link WebSessionServerOAuth2AuthorizedClientRepository}. Tests relying on
		 * {@link org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient}
		 * annotations should register an
		 * {@link WebSessionServerOAuth2AuthorizedClientRepository} bean to the
		 * application context.
		 * @param clientRegistration the {@link ClientRegistration} to use
		 * @return the {@link OAuth2LoginMutator} for further configuration
		 */
		public OAuth2LoginMutator clientRegistration(ClientRegistration clientRegistration) {
			this.clientRegistration = clientRegistration;
			return this;
		}

		@Override
		public void beforeServerCreated(WebHttpHandlerBuilder builder) {
			OAuth2AuthenticationToken token = getToken();
			mockOAuth2Client().accessToken(this.accessToken).clientRegistration(this.clientRegistration)
					.principalName(token.getPrincipal().getName()).beforeServerCreated(builder);
			mockAuthentication(token).beforeServerCreated(builder);
		}

		@Override
		public void afterConfigureAdded(WebTestClient.MockServerSpec<?> serverSpec) {
			OAuth2AuthenticationToken token = getToken();
			mockOAuth2Client().accessToken(this.accessToken).clientRegistration(this.clientRegistration)
					.principalName(token.getPrincipal().getName()).afterConfigureAdded(serverSpec);
			mockAuthentication(token).afterConfigureAdded(serverSpec);
		}

		@Override
		public void afterConfigurerAdded(WebTestClient.Builder builder,
				@Nullable WebHttpHandlerBuilder httpHandlerBuilder, @Nullable ClientHttpConnector connector) {
			OAuth2AuthenticationToken token = getToken();
			mockOAuth2Client().accessToken(this.accessToken).clientRegistration(this.clientRegistration)
					.principalName(token.getPrincipal().getName())
					.afterConfigurerAdded(builder, httpHandlerBuilder, connector);
			mockAuthentication(token).afterConfigurerAdded(builder, httpHandlerBuilder, connector);
		}

		private OAuth2AuthenticationToken getToken() {
			OAuth2User oauth2User = this.oauth2User.get();
			return new OAuth2AuthenticationToken(oauth2User, oauth2User.getAuthorities(),
					this.clientRegistration.getRegistrationId());
		}

		private ClientRegistration.Builder clientRegistrationBuilder() {
			return ClientRegistration.withRegistrationId("test").authorizationGrantType(AuthorizationGrantType.PASSWORD)
					.clientId("test-client").tokenUri("https://token-uri.example.org");
		}

		private Collection<GrantedAuthority> defaultAuthorities() {
			Set<GrantedAuthority> authorities = new LinkedHashSet<>();
			authorities.add(new OAuth2UserAuthority(this.attributes.get()));
			for (String authority : this.accessToken.getScopes()) {
				authorities.add(new SimpleGrantedAuthority("SCOPE_" + authority));
			}
			return authorities;
		}

		private Map<String, Object> defaultAttributes() {
			Map<String, Object> attributes = new HashMap<>();
			attributes.put(this.nameAttributeKey, "user");
			return attributes;
		}

		private OAuth2User defaultPrincipal() {
			return new DefaultOAuth2User(this.authorities.get(), this.attributes.get(), this.nameAttributeKey);
		}

	}

	/**
	 * @author Josh Cummings
	 * @since 5.3
	 */
	public final static class OidcLoginMutator implements WebTestClientConfigurer, MockServerConfigurer {

		private ClientRegistration clientRegistration;

		private OAuth2AccessToken accessToken;

		private OidcIdToken idToken;

		private OidcUserInfo userInfo;

		private Supplier<OidcUser> oidcUser = this::defaultPrincipal;

		private Collection<GrantedAuthority> authorities;

		ServerOAuth2AuthorizedClientRepository authorizedClientRepository = new WebSessionServerOAuth2AuthorizedClientRepository();

		private OidcLoginMutator(OAuth2AccessToken accessToken) {
			this.accessToken = accessToken;
			this.clientRegistration = clientRegistrationBuilder().build();
		}

		/**
		 * Use the provided authorities in the {@link Authentication}
		 * @param authorities the authorities to use
		 * @return the {@link OidcLoginMutator} for further configuration
		 */
		public OidcLoginMutator authorities(Collection<GrantedAuthority> authorities) {
			Assert.notNull(authorities, "authorities cannot be null");
			this.authorities = authorities;
			this.oidcUser = this::defaultPrincipal;
			return this;
		}

		/**
		 * Use the provided authorities in the {@link Authentication}
		 * @param authorities the authorities to use
		 * @return the {@link OidcLoginMutator} for further configuration
		 */
		public OidcLoginMutator authorities(GrantedAuthority... authorities) {
			Assert.notNull(authorities, "authorities cannot be null");
			this.authorities = Arrays.asList(authorities);
			this.oidcUser = this::defaultPrincipal;
			return this;
		}

		/**
		 * Use the provided {@link OidcIdToken} when constructing the authenticated user
		 * @param idTokenBuilderConsumer a {@link Consumer} of a
		 * {@link OidcIdToken.Builder}
		 * @return the {@link OidcLoginMutator} for further configuration
		 */
		public OidcLoginMutator idToken(Consumer<OidcIdToken.Builder> idTokenBuilderConsumer) {
			OidcIdToken.Builder builder = OidcIdToken.withTokenValue("id-token");
			builder.subject("user");
			idTokenBuilderConsumer.accept(builder);
			this.idToken = builder.build();
			this.oidcUser = this::defaultPrincipal;
			return this;
		}

		/**
		 * Use the provided {@link OidcUserInfo} when constructing the authenticated user
		 * @param userInfoBuilderConsumer a {@link Consumer} of a
		 * {@link OidcUserInfo.Builder}
		 * @return the {@link OidcLoginMutator} for further configuration
		 */
		public OidcLoginMutator userInfoToken(Consumer<OidcUserInfo.Builder> userInfoBuilderConsumer) {
			OidcUserInfo.Builder builder = OidcUserInfo.builder();
			userInfoBuilderConsumer.accept(builder);
			this.userInfo = builder.build();
			this.oidcUser = this::defaultPrincipal;
			return this;
		}

		/**
		 * Use the provided {@link OidcUser} as the authenticated user.
		 * <p>
		 * Supplying an {@link OidcUser} will take precedence over {@link #idToken},
		 * {@link #userInfo}, and list of {@link GrantedAuthority}s to use.
		 * @param oidcUser the {@link OidcUser} to use
		 * @return the {@link OidcLoginMutator} for further configuration
		 */
		public OidcLoginMutator oidcUser(OidcUser oidcUser) {
			this.oidcUser = () -> oidcUser;
			return this;
		}

		/**
		 * Use the provided {@link ClientRegistration} as the client to authorize.
		 * <p>
		 * The supplied {@link ClientRegistration} will be registered into an
		 * {@link WebSessionServerOAuth2AuthorizedClientRepository}. Tests relying on
		 * {@link org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient}
		 * annotations should register an
		 * {@link WebSessionServerOAuth2AuthorizedClientRepository} bean to the
		 * application context.
		 * @param clientRegistration the {@link ClientRegistration} to use
		 * @return the {@link OidcLoginMutator} for further configuration
		 */
		public OidcLoginMutator clientRegistration(ClientRegistration clientRegistration) {
			this.clientRegistration = clientRegistration;
			return this;
		}

		@Override
		public void beforeServerCreated(WebHttpHandlerBuilder builder) {
			OAuth2AuthenticationToken token = getToken();
			mockOAuth2Client().accessToken(this.accessToken).principalName(token.getPrincipal().getName())
					.clientRegistration(this.clientRegistration).beforeServerCreated(builder);
			mockAuthentication(token).beforeServerCreated(builder);
		}

		@Override
		public void afterConfigureAdded(WebTestClient.MockServerSpec<?> serverSpec) {
			OAuth2AuthenticationToken token = getToken();
			mockOAuth2Client().accessToken(this.accessToken).principalName(token.getPrincipal().getName())
					.clientRegistration(this.clientRegistration).afterConfigureAdded(serverSpec);
			mockAuthentication(token).afterConfigureAdded(serverSpec);
		}

		@Override
		public void afterConfigurerAdded(WebTestClient.Builder builder,
				@Nullable WebHttpHandlerBuilder httpHandlerBuilder, @Nullable ClientHttpConnector connector) {
			OAuth2AuthenticationToken token = getToken();
			mockOAuth2Client().accessToken(this.accessToken).principalName(token.getPrincipal().getName())
					.clientRegistration(this.clientRegistration)
					.afterConfigurerAdded(builder, httpHandlerBuilder, connector);
			mockAuthentication(token).afterConfigurerAdded(builder, httpHandlerBuilder, connector);
		}

		private ClientRegistration.Builder clientRegistrationBuilder() {
			return ClientRegistration.withRegistrationId("test").authorizationGrantType(AuthorizationGrantType.PASSWORD)
					.clientId("test-client").tokenUri("https://token-uri.example.org");
		}

		private OAuth2AuthenticationToken getToken() {
			OidcUser oidcUser = this.oidcUser.get();
			return new OAuth2AuthenticationToken(oidcUser, oidcUser.getAuthorities(),
					this.clientRegistration.getRegistrationId());
		}

		private Collection<GrantedAuthority> getAuthorities() {
			if (this.authorities == null) {
				Set<GrantedAuthority> authorities = new LinkedHashSet<>();
				authorities.add(new OidcUserAuthority(getOidcIdToken(), getOidcUserInfo()));
				for (String authority : this.accessToken.getScopes()) {
					authorities.add(new SimpleGrantedAuthority("SCOPE_" + authority));
				}
				return authorities;
			}
			else {
				return this.authorities;
			}
		}

		private OidcIdToken getOidcIdToken() {
			if (this.idToken == null) {
				return new OidcIdToken("id-token", null, null, Collections.singletonMap(IdTokenClaimNames.SUB, "user"));
			}
			else {
				return this.idToken;
			}
		}

		private OidcUserInfo getOidcUserInfo() {
			return this.userInfo;
		}

		private OidcUser defaultPrincipal() {
			return new DefaultOidcUser(getAuthorities(), getOidcIdToken(), this.userInfo);
		}

	}

	/**
	 * @author Josh Cummings
	 * @since 5.3
	 */
	public final static class OAuth2ClientMutator implements WebTestClientConfigurer, MockServerConfigurer {

		private String registrationId = "test";

		private ClientRegistration clientRegistration;

		private String principalName = "user";

		private OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				"access-token", null, null, Collections.singleton("read"));

		private ServerOAuth2AuthorizedClientRepository authorizedClientRepository = new WebSessionServerOAuth2AuthorizedClientRepository();

		private OAuth2ClientMutator() {
		}

		private OAuth2ClientMutator(String registrationId) {
			this.registrationId = registrationId;
			clientRegistration(c -> {
			});
		}

		/**
		 * Use this {@link ClientRegistration}
		 * @param clientRegistration
		 * @return the
		 * {@link SecurityMockMvcRequestPostProcessors.OAuth2ClientRequestPostProcessor}
		 * for further configuration
		 */
		public OAuth2ClientMutator clientRegistration(ClientRegistration clientRegistration) {
			this.clientRegistration = clientRegistration;
			return this;
		}

		/**
		 * Use this {@link Consumer} to configure a {@link ClientRegistration}
		 * @param clientRegistrationConfigurer the {@link ClientRegistration} configurer
		 * @return the
		 * {@link SecurityMockMvcRequestPostProcessors.OAuth2ClientRequestPostProcessor}
		 * for further configuration
		 */
		public OAuth2ClientMutator clientRegistration(
				Consumer<ClientRegistration.Builder> clientRegistrationConfigurer) {

			ClientRegistration.Builder builder = clientRegistrationBuilder();
			clientRegistrationConfigurer.accept(builder);
			this.clientRegistration = builder.build();
			return this;
		}

		/**
		 * Use this as the resource owner's principal name
		 * @param principalName the resource owner's principal name
		 * @return the {@link OAuth2ClientMutator} for further configuration
		 */
		public OAuth2ClientMutator principalName(String principalName) {
			Assert.notNull(principalName, "principalName cannot be null");
			this.principalName = principalName;
			return this;
		}

		/**
		 * Use this {@link OAuth2AccessToken}
		 * @param accessToken the {@link OAuth2AccessToken} to use
		 * @return the
		 * {@link SecurityMockMvcRequestPostProcessors.OAuth2ClientRequestPostProcessor}
		 * for further configuration
		 */
		public OAuth2ClientMutator accessToken(OAuth2AccessToken accessToken) {
			this.accessToken = accessToken;
			return this;
		}

		@Override
		public void beforeServerCreated(WebHttpHandlerBuilder builder) {
			builder.filters(addAuthorizedClientFilter());
		}

		@Override
		public void afterConfigureAdded(WebTestClient.MockServerSpec<?> serverSpec) {

		}

		@Override
		public void afterConfigurerAdded(WebTestClient.Builder builder,
				@Nullable WebHttpHandlerBuilder httpHandlerBuilder, @Nullable ClientHttpConnector connector) {
			httpHandlerBuilder.filters(addAuthorizedClientFilter());
		}

		private Consumer<List<WebFilter>> addAuthorizedClientFilter() {
			OAuth2AuthorizedClient client = getClient();
			return filters -> filters.add(0, (exchange, chain) -> {
				ReactiveOAuth2AuthorizedClientManager authorizationClientManager = OAuth2ClientServerTestUtils
						.getOAuth2AuthorizedClientManager(exchange);
				if (!(authorizationClientManager instanceof TestReactiveOAuth2AuthorizedClientManager)) {
					authorizationClientManager = new TestReactiveOAuth2AuthorizedClientManager(
							authorizationClientManager);
					OAuth2ClientServerTestUtils.setOAuth2AuthorizedClientManager(exchange, authorizationClientManager);
				}
				TestReactiveOAuth2AuthorizedClientManager.enable(exchange);
				exchange.getAttributes().put(TestReactiveOAuth2AuthorizedClientManager.TOKEN_ATTR_NAME, client);
				return chain.filter(exchange);
			});
		}

		private OAuth2AuthorizedClient getClient() {
			if (this.clientRegistration == null) {
				throw new IllegalArgumentException(
						"Please specify a ClientRegistration via one " + "of the clientRegistration methods");
			}
			return new OAuth2AuthorizedClient(this.clientRegistration, this.principalName, this.accessToken);
		}

		private ClientRegistration.Builder clientRegistrationBuilder() {
			return ClientRegistration.withRegistrationId(this.registrationId)
					.authorizationGrantType(AuthorizationGrantType.PASSWORD).clientId("test-client")
					.clientSecret("test-secret").tokenUri("https://idp.example.org/oauth/token");
		}

		/**
		 * Used to wrap the {@link OAuth2AuthorizedClientManager} to provide support for
		 * testing when the request is wrapped
		 */
		private static final class TestReactiveOAuth2AuthorizedClientManager
				implements ReactiveOAuth2AuthorizedClientManager {

			final static String TOKEN_ATTR_NAME = TestReactiveOAuth2AuthorizedClientManager.class.getName()
					.concat(".TOKEN");

			final static String ENABLED_ATTR_NAME = TestReactiveOAuth2AuthorizedClientManager.class.getName()
					.concat(".ENABLED");

			private final ReactiveOAuth2AuthorizedClientManager delegate;

			private TestReactiveOAuth2AuthorizedClientManager(ReactiveOAuth2AuthorizedClientManager delegate) {
				this.delegate = delegate;
			}

			@Override
			public Mono<OAuth2AuthorizedClient> authorize(OAuth2AuthorizeRequest authorizeRequest) {
				ServerWebExchange exchange = authorizeRequest.getAttribute(ServerWebExchange.class.getName());
				if (isEnabled(exchange)) {
					OAuth2AuthorizedClient client = exchange.getAttribute(TOKEN_ATTR_NAME);
					return Mono.just(client);
				}
				else {
					return this.delegate.authorize(authorizeRequest);
				}
			}

			public static void enable(ServerWebExchange exchange) {
				exchange.getAttributes().put(ENABLED_ATTR_NAME, TRUE);
			}

			public boolean isEnabled(ServerWebExchange exchange) {
				return TRUE.equals(exchange.getAttribute(ENABLED_ATTR_NAME));
			}

		}

		private static final class OAuth2ClientServerTestUtils {

			private static final ServerOAuth2AuthorizedClientRepository DEFAULT_CLIENT_REPO = new WebSessionServerOAuth2AuthorizedClientRepository();

			private OAuth2ClientServerTestUtils() {
			}

			/**
			 * Gets the {@link ReactiveOAuth2AuthorizedClientManager} for the specified
			 * {@link ServerWebExchange}. If one is not found, one based off of
			 * {@link WebSessionServerOAuth2AuthorizedClientRepository} is used.
			 * @param exchange the {@link ServerWebExchange} to obtain the
			 * {@link ReactiveOAuth2AuthorizedClientManager}
			 * @return the {@link ReactiveOAuth2AuthorizedClientManager} for the specified
			 * {@link ServerWebExchange}
			 */
			public static ReactiveOAuth2AuthorizedClientManager getOAuth2AuthorizedClientManager(
					ServerWebExchange exchange) {
				OAuth2AuthorizedClientArgumentResolver resolver = findResolver(exchange,
						OAuth2AuthorizedClientArgumentResolver.class);
				if (resolver == null) {
					return authorizeRequest -> DEFAULT_CLIENT_REPO.loadAuthorizedClient(
							authorizeRequest.getClientRegistrationId(), authorizeRequest.getPrincipal(), exchange);
				}
				return (ReactiveOAuth2AuthorizedClientManager) ReflectionTestUtils.getField(resolver,
						"authorizedClientManager");
			}

			/**
			 * Sets the {@link ReactiveOAuth2AuthorizedClientManager} for the specified
			 * {@link ServerWebExchange}.
			 * @param exchange the {@link ServerWebExchange} to obtain the
			 * {@link ReactiveOAuth2AuthorizedClientManager}
			 * @param manager the {@link ReactiveOAuth2AuthorizedClientManager} to set
			 */
			public static void setOAuth2AuthorizedClientManager(ServerWebExchange exchange,
					ReactiveOAuth2AuthorizedClientManager manager) {
				OAuth2AuthorizedClientArgumentResolver resolver = findResolver(exchange,
						OAuth2AuthorizedClientArgumentResolver.class);
				if (resolver == null) {
					return;
				}
				ReflectionTestUtils.setField(resolver, "authorizedClientManager", manager);
			}

			@SuppressWarnings("unchecked")
			static <T extends HandlerMethodArgumentResolver> T findResolver(ServerWebExchange exchange,
					Class<T> resolverClass) {
				if (!ClassUtils.isPresent(
						"org.springframework.web.reactive.result.method.annotation.RequestMappingHandlerAdapter",
						null)) {
					return null;
				}
				return WebFluxClasspathGuard.findResolver(exchange, resolverClass);
			}

			private static class WebFluxClasspathGuard {

				static <T extends HandlerMethodArgumentResolver> T findResolver(ServerWebExchange exchange,
						Class<T> resolverClass) {
					RequestMappingHandlerAdapter handlerAdapter = getRequestMappingHandlerAdapter(exchange);
					if (handlerAdapter == null) {
						return null;
					}
					ArgumentResolverConfigurer configurer = handlerAdapter.getArgumentResolverConfigurer();
					if (configurer == null) {
						return null;
					}
					List<HandlerMethodArgumentResolver> resolvers = (List<HandlerMethodArgumentResolver>) ReflectionTestUtils
							.invokeGetterMethod(configurer, "customResolvers");
					if (resolvers == null) {
						return null;
					}
					for (HandlerMethodArgumentResolver resolver : resolvers) {
						if (resolverClass.isAssignableFrom(resolver.getClass())) {
							return (T) resolver;
						}
					}
					return null;
				}

				private static RequestMappingHandlerAdapter getRequestMappingHandlerAdapter(
						ServerWebExchange exchange) {
					ApplicationContext context = exchange.getApplicationContext();
					if (context != null) {
						String[] names = context.getBeanNamesForType(RequestMappingHandlerAdapter.class);
						if (names.length > 0) {
							return (RequestMappingHandlerAdapter) context.getBean(names[0]);
						}
					}
					return null;
				}

			}

		}

	}

}
