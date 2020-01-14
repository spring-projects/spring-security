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

import reactor.core.publisher.Mono;

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
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.WebSessionServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
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
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.server.csrf.CsrfWebFilter;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.test.web.reactive.server.MockServerConfigurer;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.test.web.reactive.server.WebTestClientConfigurer;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.server.adapter.WebHttpHandlerBuilder;

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
			public void beforeServerCreated(WebHttpHandlerBuilder builder) {
				builder.filters( filters -> filters.add(0, new MutatorFilter()));
			}
		};
	}

	/**
	 * Updates the ServerWebExchange to use the provided Authentication as the Principal
	 *
	 * @param authentication the Authentication to use.
	 * @return the configurer to use
	 */
	public static <T extends WebTestClientConfigurer & MockServerConfigurer> T mockAuthentication(Authentication authentication) {
		return (T) new MutatorWebTestClientConfigurer(() -> Mono.just(authentication).map(SecurityContextImpl::new));
	}

	/**
	 * Updates the ServerWebExchange to use the provided UserDetails to create a UsernamePasswordAuthenticationToken as
	 * the Principal
	 *
	 * @param userDetails the UserDetails to use.
	 * @return the configurer to use
	 */
	public static <T extends WebTestClientConfigurer & MockServerConfigurer> T mockUser(UserDetails userDetails) {
		return mockAuthentication(new UsernamePasswordAuthenticationToken(userDetails, userDetails.getPassword(), userDetails.getAuthorities()));
	}

	/**
	 * Updates the ServerWebExchange to use a UserDetails to create a UsernamePasswordAuthenticationToken as
	 * the Principal. This uses a default username of "user", password of "password", and granted authorities of
	 * "ROLE_USER".
	 *
	 * @return the {@link UserExchangeMutator} to use
	 */
	public static UserExchangeMutator mockUser() {
		return mockUser("user");
	}


	/**
	 * Updates the ServerWebExchange to use a UserDetails to create a UsernamePasswordAuthenticationToken as
	 * the Principal. This uses a default password of "password" and granted authorities of
	 * "ROLE_USER".
	 *
	 * @return the {@link WebTestClientConfigurer} to use
	 */
	public static UserExchangeMutator mockUser(String username) {
		return new UserExchangeMutator(username);
	}

	/**
	 * Updates the ServerWebExchange to establish a {@link SecurityContext} that has a
	 * {@link JwtAuthenticationToken} for the
	 * {@link Authentication} and a {@link Jwt} for the
	 * {@link Authentication#getPrincipal()}. All details are
	 * declarative and do not require the JWT to be valid.
	 *
	 * @return the {@link JwtMutator} to further configure or use
	 * @since 5.2
	 */
	public static JwtMutator mockJwt() {
		return new JwtMutator();
	}

	/**
	 * Updates the ServerWebExchange to establish a {@link SecurityContext} that has a
	 * {@link OAuth2AuthenticationToken} for the
	 * {@link Authentication}. All details are
	 * declarative and do not require the corresponding OAuth 2.0 tokens to be valid.
	 *
	 * @return the {@link OAuth2LoginMutator} to further configure or use
	 * @since 5.3
	 */
	public static OAuth2LoginMutator mockOAuth2Login() {
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-token",
				null, null, Collections.singleton("user"));
		return new OAuth2LoginMutator(accessToken);
	}

	/**
	 * Updates the ServerWebExchange to establish a {@link SecurityContext} that has a
	 * {@link OAuth2AuthenticationToken} for the
	 * {@link Authentication}. All details are
	 * declarative and do not require the corresponding OAuth 2.0 tokens to be valid.
	 *
	 * @return the {@link OidcLoginMutator} to further configure or use
	 * @since 5.3
	 */
	public static OidcLoginMutator mockOidcLogin() {
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-token",
				null, null, Collections.singleton("user"));
		return new OidcLoginMutator(accessToken);
	}

	public static CsrfMutator csrf() {
		return new CsrfMutator();
	}

	public static class CsrfMutator implements WebTestClientConfigurer, MockServerConfigurer {

		@Override
		public void afterConfigurerAdded(WebTestClient.Builder builder,
			@Nullable WebHttpHandlerBuilder httpHandlerBuilder,
			@Nullable ClientHttpConnector connector) {
			CsrfWebFilter filter = new CsrfWebFilter();
			filter.setRequireCsrfProtectionMatcher( e -> ServerWebExchangeMatcher.MatchResult.notMatch());
			httpHandlerBuilder.filters( filters -> filters.add(0, filter));
		}

		@Override
		public void afterConfigureAdded(
			WebTestClient.MockServerSpec<?> serverSpec) {

		}

		@Override
		public void beforeServerCreated(WebHttpHandlerBuilder builder) {

		}

		private CsrfMutator() {}
	}

	/**
	 * Updates the WebServerExchange using {@code {@link SecurityMockServerConfigurers#mockUser(UserDetails)}}. Defaults to use a
	 * password of "password" and granted authorities of "ROLE_USER".
	 */
	public static class UserExchangeMutator implements WebTestClientConfigurer, MockServerConfigurer {
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
		 * Specifies the roles to use. Default is "USER". This is similar to authorities except each role is
		 * automatically prefixed with "ROLE_USER".
		 *
		 * @param roles the roles to use.
		 * @return the UserExchangeMutator
		 */
		public UserExchangeMutator roles(String... roles) {
			this.userBuilder.roles(roles);
			return this;
		}

		/**
		 * Specifies the {@code GrantedAuthority}s to use. Default is "ROLE_USER".
		 *
		 * @param authorities the authorities to use.
		 * @return the UserExchangeMutator
		 */
		public UserExchangeMutator authorities(GrantedAuthority... authorities) {
			this.userBuilder.authorities(authorities);
			return this;
		}

		/**
		 * Specifies the {@code GrantedAuthority}s to use. Default is "ROLE_USER".
		 *
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
		public void afterConfigurerAdded(WebTestClient.Builder builder, @Nullable WebHttpHandlerBuilder webHttpHandlerBuilder, @Nullable ClientHttpConnector clientHttpConnector) {
			configurer().afterConfigurerAdded(builder, webHttpHandlerBuilder, clientHttpConnector);
		}

		private <T extends WebTestClientConfigurer & MockServerConfigurer> T configurer() {
			return mockUser(this.userBuilder.build());
		}
	}

	private static class MutatorWebTestClientConfigurer implements WebTestClientConfigurer, MockServerConfigurer {
		private final Supplier<Mono<SecurityContext>> context;

		private MutatorWebTestClientConfigurer(Supplier<Mono<SecurityContext>> context) {
			this.context = context;
		}
		@Override
		public void beforeServerCreated(WebHttpHandlerBuilder builder) {
			builder.filters(addSetupMutatorFilter());
		}

		@Override
		public void afterConfigurerAdded(WebTestClient.Builder builder, @Nullable WebHttpHandlerBuilder webHttpHandlerBuilder, @Nullable ClientHttpConnector clientHttpConnector) {
			webHttpHandlerBuilder.filters(addSetupMutatorFilter());
		}

		private Consumer<List<WebFilter>> addSetupMutatorFilter() {
			return filters -> filters.add(0, new SetupMutatorFilter(this.context));
		}
	}

	private static class SetupMutatorFilter implements WebFilter {
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
	 * Updates the WebServerExchange using
	 * {@code {@link SecurityMockServerConfigurers#mockAuthentication(Authentication)}}.
	 *
	 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
	 * @author Josh Cummings
	 * @since 5.2
	 */
	public static class JwtMutator implements WebTestClientConfigurer, MockServerConfigurer {
		private Jwt jwt;
		private Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter =
				new JwtGrantedAuthoritiesConverter();

		private JwtMutator() {
			jwt((jwt) -> {});
		}

		/**
		 * Use the given {@link Jwt.Builder} {@link Consumer} to configure the underlying {@link Jwt}
		 *
		 * This method first creates a default {@link Jwt.Builder} instance with default values for
		 * the {@code alg}, {@code sub}, and {@code scope} claims. The {@link Consumer} can then modify
		 * these or provide additional configuration.
		 *
		 * Calling {@link SecurityMockServerConfigurers#mockJwt()} is the equivalent of calling
		 * {@code SecurityMockMvcRequestPostProcessors.mockJwt().jwt(() -> {})}.
		 *
		 * @param jwtBuilderConsumer For configuring the underlying {@link Jwt}
		 * @return the {@link JwtMutator} for further configuration
		 */
		public JwtMutator jwt(Consumer<Jwt.Builder> jwtBuilderConsumer) {
			Jwt.Builder jwtBuilder = Jwt.withTokenValue("token")
					.header("alg", "none")
					.claim(SUB, "user")
					.claim("scope", "read");
			jwtBuilderConsumer.accept(jwtBuilder);
			this.jwt = jwtBuilder.build();
			return this;
		}

		/**
		 * Use the given {@link Jwt}
		 *
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
		 *
		 * @param authoritiesConverter the conversion strategy from {@link Jwt} to a {@link Collection}
		 * of {@link GrantedAuthority}s
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
		public void afterConfigurerAdded(
				WebTestClient.Builder builder,
				@Nullable WebHttpHandlerBuilder httpHandlerBuilder,
				@Nullable ClientHttpConnector connector) {
			httpHandlerBuilder.filter((exchange, chain) -> {
				CsrfWebFilter.skipExchange(exchange);
				return chain.filter(exchange);
			});
			configurer().afterConfigurerAdded(builder, httpHandlerBuilder, connector);
		}

		private <T extends WebTestClientConfigurer & MockServerConfigurer> T configurer() {
			return mockAuthentication(new JwtAuthenticationToken(this.jwt, this.authoritiesConverter.convert(this.jwt)));
		}
	}

	/**
	 * @author Josh Cummings
	 * @since 5.3
	 */
	public final static class OAuth2LoginMutator implements WebTestClientConfigurer, MockServerConfigurer {
		private ClientRegistration clientRegistration;
		private OAuth2AccessToken accessToken;

		private Supplier<Collection<GrantedAuthority>> authorities = this::defaultAuthorities;
		private Supplier<Map<String, Object>> attributes = this::defaultAttributes;
		private String nameAttributeKey = "sub";
		private Supplier<OAuth2User> oauth2User = this::defaultPrincipal;

		private final ServerOAuth2AuthorizedClientRepository authorizedClientRepository =
				new WebSessionServerOAuth2AuthorizedClientRepository();

		private OAuth2LoginMutator(OAuth2AccessToken accessToken) {
			this.accessToken = accessToken;
			this.clientRegistration = clientRegistrationBuilder().build();
		}

		/**
		 * Use the provided authorities in the {@link Authentication}
		 *
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
		 *
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
		 *
		 * @param attributesConsumer The {@link Consumer} for mutating the {@Map} of attributes
		 * @return the {@link OAuth2LoginMutator} for further configuration
		 */
		public OAuth2LoginMutator attributes(Consumer<Map<String, Object>> attributesConsumer) {
			Assert.notNull(attributesConsumer, "attributesConsumer cannot be null");
			this.attributes = () -> {
				Map<String, Object> attrs = new HashMap<>();
				attrs.put(this.nameAttributeKey, "test-subject");
				attributesConsumer.accept(attrs);
				return attrs;
			};
			this.oauth2User = this::defaultPrincipal;
			return this;
		}

		/**
		 * Use the provided key for the attribute containing the principal's name
		 *
		 * @param nameAttributeKey The attribute key to use
		 * @return the {@link OAuth2LoginMutator} for further configuration
		 */
		public OAuth2LoginMutator nameAttributeKey(String nameAttributeKey) {
			Assert.notNull(nameAttributeKey, "nameAttributeKey cannot be null");
			this.nameAttributeKey = nameAttributeKey;
			this.oauth2User = this::defaultPrincipal;
			return this;
		}

		/**
		 * Use the provided {@link OAuth2User} as the authenticated user.
		 *
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
		 * annotations should register an {@link WebSessionServerOAuth2AuthorizedClientRepository} bean
		 * to the application context.
		 *
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
			builder.filters(addAuthorizedClientFilter(token));
			mockAuthentication(getToken()).beforeServerCreated(builder);
		}

		@Override
		public void afterConfigureAdded(WebTestClient.MockServerSpec<?> serverSpec) {
			mockAuthentication(getToken()).afterConfigureAdded(serverSpec);
		}

		@Override
		public void afterConfigurerAdded(
				WebTestClient.Builder builder,
				@Nullable WebHttpHandlerBuilder httpHandlerBuilder,
				@Nullable ClientHttpConnector connector) {
			OAuth2AuthenticationToken token = getToken();
			httpHandlerBuilder.filters(addAuthorizedClientFilter(token));
			mockAuthentication(token).afterConfigurerAdded(builder, httpHandlerBuilder, connector);
		}

		private Consumer<List<WebFilter>> addAuthorizedClientFilter(OAuth2AuthenticationToken token) {
			OAuth2AuthorizedClient client = getClient();
			return filters -> filters.add(0, (exchange, chain) ->
					this.authorizedClientRepository.saveAuthorizedClient(client, token, exchange)
							.then(chain.filter(exchange)));
		}

		private OAuth2AuthenticationToken getToken() {
			OAuth2User oauth2User = this.oauth2User.get();
			return new OAuth2AuthenticationToken(oauth2User, oauth2User.getAuthorities(), this.clientRegistration.getRegistrationId());
		}

		private OAuth2AuthorizedClient getClient() {
			return new OAuth2AuthorizedClient(this.clientRegistration, getToken().getName(), this.accessToken);
		}

		private ClientRegistration.Builder clientRegistrationBuilder() {
			return ClientRegistration.withRegistrationId("test")
					.authorizationGrantType(AuthorizationGrantType.PASSWORD)
					.clientId("test-client")
					.tokenUri("https://token-uri.example.org");
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
			return Collections.singletonMap(this.nameAttributeKey, "test-subject");
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

		ServerOAuth2AuthorizedClientRepository authorizedClientRepository =
				new WebSessionServerOAuth2AuthorizedClientRepository();

		private OidcLoginMutator(OAuth2AccessToken accessToken) {
			this.accessToken = accessToken;
			this.clientRegistration = clientRegistrationBuilder().build();
		}

		/**
		 * Use the provided authorities in the {@link Authentication}
		 *
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
		 *
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
		 *
		 * @param idTokenBuilderConsumer a {@link Consumer} of a {@link OidcIdToken.Builder}
		 * @return the {@link OidcLoginMutator} for further configuration
		 */
		public OidcLoginMutator idToken(Consumer<OidcIdToken.Builder> idTokenBuilderConsumer) {
			OidcIdToken.Builder builder = OidcIdToken.withTokenValue("id-token");
			builder.subject("test-subject");
			idTokenBuilderConsumer.accept(builder);
			this.idToken = builder.build();
			this.oidcUser = this::defaultPrincipal;
			return this;
		}

		/**
		 * Use the provided {@link OidcUserInfo} when constructing the authenticated user
		 *
		 * @param userInfoBuilderConsumer a {@link Consumer} of a {@link OidcUserInfo.Builder}
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
		 * Supplying an {@link OidcUser} will take precedence over {@link #idToken}, {@link #userInfo},
		 * and list of {@link GrantedAuthority}s to use.
		 *
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
		 * annotations should register an {@link WebSessionServerOAuth2AuthorizedClientRepository} bean
		 * to the application context.
		 *
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
			builder.filters(addAuthorizedClientFilter(token));
			mockAuthentication(getToken()).beforeServerCreated(builder);
		}

		@Override
		public void afterConfigureAdded(WebTestClient.MockServerSpec<?> serverSpec) {
			mockAuthentication(getToken()).afterConfigureAdded(serverSpec);
		}

		@Override
		public void afterConfigurerAdded(
				WebTestClient.Builder builder,
				@Nullable WebHttpHandlerBuilder httpHandlerBuilder,
				@Nullable ClientHttpConnector connector) {
			OAuth2AuthenticationToken token = getToken();
			httpHandlerBuilder.filters(addAuthorizedClientFilter(token));
			mockAuthentication(token).afterConfigurerAdded(builder, httpHandlerBuilder, connector);
		}

		private Consumer<List<WebFilter>> addAuthorizedClientFilter(OAuth2AuthenticationToken token) {
			OAuth2AuthorizedClient client = getClient();
			return filters -> filters.add(0, (exchange, chain) ->
					authorizedClientRepository.saveAuthorizedClient(client, token, exchange)
							.then(chain.filter(exchange)));
		}

		private ClientRegistration.Builder clientRegistrationBuilder() {
			return ClientRegistration.withRegistrationId("test")
					.authorizationGrantType(AuthorizationGrantType.PASSWORD)
					.clientId("test-client")
					.tokenUri("https://token-uri.example.org");
		}

		private OAuth2AuthenticationToken getToken() {
			OidcUser oidcUser = this.oidcUser.get();
			return new OAuth2AuthenticationToken(oidcUser, oidcUser.getAuthorities(), this.clientRegistration.getRegistrationId());
		}

		private OAuth2AuthorizedClient getClient() {
			return new OAuth2AuthorizedClient(this.clientRegistration, getToken().getName(), this.accessToken);
		}

		private Collection<GrantedAuthority> getAuthorities() {
			if (this.authorities == null) {
				Set<GrantedAuthority> authorities = new LinkedHashSet<>();
				authorities.add(new OidcUserAuthority(getOidcIdToken(), getOidcUserInfo()));
				for (String authority : this.accessToken.getScopes()) {
					authorities.add(new SimpleGrantedAuthority("SCOPE_" + authority));
				}
				return authorities;
			} else {
				return this.authorities;
			}
		}

		private OidcIdToken getOidcIdToken() {
			if (this.idToken == null) {
				return new OidcIdToken("id-token", null, null, Collections.singletonMap(IdTokenClaimNames.SUB, "test-subject"));
			} else {
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
}
