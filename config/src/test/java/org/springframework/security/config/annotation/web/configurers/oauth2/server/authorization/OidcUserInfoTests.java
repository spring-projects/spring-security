/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Function;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultMatcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for the OpenID Connect 1.0 UserInfo endpoint.
 *
 * @author Steve Riesenberg
 */
@ExtendWith(SpringTestContextExtension.class)
public class OidcUserInfoTests {

	private static final String DEFAULT_OIDC_USER_INFO_ENDPOINT_URI = "/userinfo";

	private static SecurityContextRepository securityContextRepository;

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private MockMvc mvc;

	@Autowired
	private JwtEncoder jwtEncoder;

	@Autowired
	private JwtDecoder jwtDecoder;

	@Autowired
	private OAuth2AuthorizationService authorizationService;

	private static AuthenticationConverter authenticationConverter;

	private static Consumer<List<AuthenticationConverter>> authenticationConvertersConsumer;

	private static AuthenticationProvider authenticationProvider;

	private static Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer;

	private static AuthenticationSuccessHandler authenticationSuccessHandler;

	private static AuthenticationFailureHandler authenticationFailureHandler;

	private static Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper;

	@BeforeAll
	public static void init() {
		securityContextRepository = spy(new HttpSessionSecurityContextRepository());
		authenticationConverter = mock(AuthenticationConverter.class);
		authenticationConvertersConsumer = mock(Consumer.class);
		authenticationProvider = mock(AuthenticationProvider.class);
		authenticationProvidersConsumer = mock(Consumer.class);
		authenticationSuccessHandler = mock(AuthenticationSuccessHandler.class);
		authenticationFailureHandler = mock(AuthenticationFailureHandler.class);
		userInfoMapper = mock(Function.class);
	}

	@BeforeEach
	public void setup() {
		reset(securityContextRepository);
		reset(authenticationConverter);
		reset(authenticationConvertersConsumer);
		reset(authenticationProvider);
		reset(authenticationProvidersConsumer);
		reset(authenticationSuccessHandler);
		reset(authenticationFailureHandler);
		reset(userInfoMapper);
	}

	@Test
	public void requestWhenUserInfoRequestGetThenUserInfoResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		OAuth2Authorization authorization = createAuthorization();
		this.authorizationService.save(authorization);

		OAuth2AccessToken accessToken = authorization.getAccessToken().getToken();
		// @formatter:off
		this.mvc.perform(get(DEFAULT_OIDC_USER_INFO_ENDPOINT_URI)
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getTokenValue()))
				.andExpect(status().is2xxSuccessful())
				.andExpectAll(userInfoResponse());
		// @formatter:on
	}

	@Test
	public void requestWhenUserInfoRequestPostThenUserInfoResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		OAuth2Authorization authorization = createAuthorization();
		this.authorizationService.save(authorization);

		OAuth2AccessToken accessToken = authorization.getAccessToken().getToken();
		// @formatter:off
		this.mvc.perform(post(DEFAULT_OIDC_USER_INFO_ENDPOINT_URI)
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getTokenValue()))
				.andExpect(status().is2xxSuccessful())
				.andExpectAll(userInfoResponse());
		// @formatter:on
	}

	@Test
	public void requestWhenUserInfoRequestIncludesIssuerPathThenUserInfoResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		OAuth2Authorization authorization = createAuthorization();
		this.authorizationService.save(authorization);

		String issuer = "https://example.com:8443/issuer1";

		OAuth2AccessToken accessToken = authorization.getAccessToken().getToken();
		// @formatter:off
		this.mvc.perform(get(issuer.concat(DEFAULT_OIDC_USER_INFO_ENDPOINT_URI))
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getTokenValue()))
				.andExpect(status().is2xxSuccessful())
				.andExpectAll(userInfoResponse());
		// @formatter:on
	}

	@Test
	public void requestWhenUserInfoEndpointCustomizedThenUsed() throws Exception {
		this.spring.register(CustomUserInfoConfiguration.class).autowire();

		OAuth2Authorization authorization = createAuthorization();
		this.authorizationService.save(authorization);

		given(userInfoMapper.apply(any())).willReturn(createUserInfo());

		OAuth2AccessToken accessToken = authorization.getAccessToken().getToken();
		// @formatter:off
		this.mvc.perform(get(DEFAULT_OIDC_USER_INFO_ENDPOINT_URI)
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getTokenValue()))
				.andExpect(status().is2xxSuccessful());
		// @formatter:on

		verify(userInfoMapper).apply(any());
		verify(authenticationConverter).convert(any());
		verify(authenticationSuccessHandler).onAuthenticationSuccess(any(), any(), any());
		verifyNoInteractions(authenticationFailureHandler);

		ArgumentCaptor<List<AuthenticationProvider>> authenticationProvidersCaptor = ArgumentCaptor
			.forClass(List.class);
		verify(authenticationProvidersConsumer).accept(authenticationProvidersCaptor.capture());
		List<AuthenticationProvider> authenticationProviders = authenticationProvidersCaptor.getValue();
		assertThat(authenticationProviders).hasSize(2)
			.allMatch((provider) -> provider == authenticationProvider
					|| provider instanceof OidcUserInfoAuthenticationProvider);

		ArgumentCaptor<List<AuthenticationConverter>> authenticationConvertersCaptor = ArgumentCaptor
			.forClass(List.class);
		verify(authenticationConvertersConsumer).accept(authenticationConvertersCaptor.capture());
		List<AuthenticationConverter> authenticationConverters = authenticationConvertersCaptor.getValue();
		assertThat(authenticationConverters).hasSize(2).allMatch(AuthenticationConverter.class::isInstance);
	}

	@Test
	public void requestWhenUserInfoEndpointCustomizedWithAuthenticationProviderThenUsed() throws Exception {
		this.spring.register(CustomUserInfoConfiguration.class).autowire();

		OAuth2Authorization authorization = createAuthorization();
		this.authorizationService.save(authorization);

		given(authenticationProvider.supports(eq(OidcUserInfoAuthenticationToken.class))).willReturn(true);
		String tokenValue = authorization.getAccessToken().getToken().getTokenValue();
		Jwt jwt = this.jwtDecoder.decode(tokenValue);
		OidcUserInfoAuthenticationToken oidcUserInfoAuthentication = new OidcUserInfoAuthenticationToken(
				new JwtAuthenticationToken(jwt), createUserInfo());
		given(authenticationProvider.authenticate(any())).willReturn(oidcUserInfoAuthentication);

		OAuth2AccessToken accessToken = authorization.getAccessToken().getToken();
		// @formatter:off
		this.mvc.perform(get(DEFAULT_OIDC_USER_INFO_ENDPOINT_URI)
						.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getTokenValue()))
				.andExpect(status().is2xxSuccessful());
		// @formatter:on

		verify(authenticationSuccessHandler).onAuthenticationSuccess(any(), any(), any());
		verify(authenticationProvider).authenticate(any());
		verifyNoInteractions(authenticationFailureHandler);
		verifyNoInteractions(userInfoMapper);
	}

	@Test
	public void requestWhenUserInfoEndpointCustomizedWithAuthenticationFailureHandlerThenUsed() throws Exception {
		this.spring.register(CustomUserInfoConfiguration.class).autowire();

		given(userInfoMapper.apply(any())).willReturn(createUserInfo());
		willAnswer((invocation) -> {
			HttpServletResponse response = invocation.getArgument(1);
			response.setStatus(HttpStatus.UNAUTHORIZED.value());
			response.getWriter().write("unauthorized");
			return null;
		}).given(authenticationFailureHandler).onAuthenticationFailure(any(), any(), any());

		OAuth2AccessToken accessToken = createAuthorization().getAccessToken().getToken();
		// @formatter:off
		this.mvc.perform(get(DEFAULT_OIDC_USER_INFO_ENDPOINT_URI)
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getTokenValue()))
				.andExpect(status().is4xxClientError());
		// @formatter:on

		verify(authenticationFailureHandler).onAuthenticationFailure(any(), any(), any());
		verifyNoInteractions(authenticationSuccessHandler);
		verifyNoInteractions(userInfoMapper);
	}

	// gh-482
	@Test
	public void requestWhenUserInfoRequestThenBearerTokenAuthenticationNotPersisted() throws Exception {
		this.spring.register(AuthorizationServerConfigurationWithSecurityContextRepository.class).autowire();

		OAuth2Authorization authorization = createAuthorization();
		this.authorizationService.save(authorization);

		OAuth2AccessToken accessToken = authorization.getAccessToken().getToken();
		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(get(DEFAULT_OIDC_USER_INFO_ENDPOINT_URI)
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getTokenValue()))
				.andExpect(status().is2xxSuccessful())
				.andExpectAll(userInfoResponse())
				.andReturn();
		// @formatter:on

		org.springframework.security.core.context.SecurityContext securityContext = securityContextRepository
			.loadDeferredContext(mvcResult.getRequest())
			.get();
		assertThat(securityContext.getAuthentication()).isNull();
	}

	private static ResultMatcher[] userInfoResponse() {
		// @formatter:off
		return new ResultMatcher[] {
				jsonPath("sub").value("user1"),
				jsonPath("name").value("First Last"),
				jsonPath("given_name").value("First"),
				jsonPath("family_name").value("Last"),
				jsonPath("middle_name").value("Middle"),
				jsonPath("nickname").value("User"),
				jsonPath("preferred_username").value("user"),
				jsonPath("profile").value("https://example.com/user1"),
				jsonPath("picture").value("https://example.com/user1.jpg"),
				jsonPath("website").value("https://example.com"),
				jsonPath("email").value("user1@example.com"),
				jsonPath("email_verified").value("true"),
				jsonPath("gender").value("female"),
				jsonPath("birthdate").value("1970-01-01"),
				jsonPath("zoneinfo").value("Europe/Paris"),
				jsonPath("locale").value("en-US"),
				jsonPath("phone_number").value("+1 (604) 555-1234;ext=5678"),
				jsonPath("phone_number_verified").value("false"),
				jsonPath("address.formatted").value("Champ de Mars\n5 Av. Anatole France\n75007 Paris\nFrance"),
				jsonPath("updated_at").value("1970-01-01T00:00:00Z")
		};
		// @formatter:on
	}

	private OAuth2Authorization createAuthorization() {
		JwsHeader headers = JwsHeader.with(SignatureAlgorithm.RS256).build();
		// @formatter:off
		JwtClaimsSet claimSet = JwtClaimsSet.builder()
				.claims((claims) -> claims.putAll(createUserInfo().getClaims()))
				.build();
		// @formatter:on
		Jwt jwt = this.jwtEncoder.encode(JwtEncoderParameters.from(headers, claimSet));

		Instant now = Instant.now();
		Set<String> scopes = new HashSet<>(Arrays.asList(OidcScopes.OPENID, OidcScopes.ADDRESS, OidcScopes.EMAIL,
				OidcScopes.PHONE, OidcScopes.PROFILE));
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, jwt.getTokenValue(),
				now, now.plusSeconds(300), scopes);
		OidcIdToken idToken = OidcIdToken.withTokenValue("id-token")
			.claims((claims) -> claims.putAll(createUserInfo().getClaims()))
			.build();

		return TestOAuth2Authorizations.authorization().accessToken(accessToken).token(idToken).build();
	}

	private static OidcUserInfo createUserInfo() {
		// @formatter:off
		return OidcUserInfo.builder()
				.subject("user1")
				.name("First Last")
				.givenName("First")
				.familyName("Last")
				.middleName("Middle")
				.nickname("User")
				.preferredUsername("user")
				.profile("https://example.com/user1")
				.picture("https://example.com/user1.jpg")
				.website("https://example.com")
				.email("user1@example.com")
				.emailVerified(true)
				.gender("female")
				.birthdate("1970-01-01")
				.zoneinfo("Europe/Paris")
				.locale("en-US")
				.phoneNumber("+1 (604) 555-1234;ext=5678")
				.phoneNumberVerified(false)
				.claim("address", Collections.singletonMap("formatted", "Champ de Mars\n5 Av. Anatole France\n75007 Paris\nFrance"))
				.updatedAt("1970-01-01T00:00:00Z")
				.build();
		// @formatter:on
	}

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
	static class CustomUserInfoConfiguration extends AuthorizationServerConfiguration {

		@Bean
		@Override
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.oauth2AuthorizationServer((authorizationServer) ->
							authorizationServer
									.oidc((oidc) ->
											oidc
													.userInfoEndpoint((userInfo) ->
															userInfo
																	.userInfoRequestConverter(authenticationConverter)
																	.userInfoRequestConverters(authenticationConvertersConsumer)
																	.authenticationProvider(authenticationProvider)
																	.authenticationProviders(authenticationProvidersConsumer)
																	.userInfoResponseHandler(authenticationSuccessHandler)
																	.errorResponseHandler(authenticationFailureHandler)
																	.userInfoMapper(userInfoMapper)))
					)
					.authorizeHttpRequests((authorize) ->
							authorize.anyRequest().authenticated()
					);
			// @formatter:on
			return http.build();
		}

	}

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
	static class AuthorizationServerConfigurationWithSecurityContextRepository
			extends AuthorizationServerConfiguration {

		@Bean
		@Override
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.oauth2AuthorizationServer((authorizationServer) ->
							authorizationServer
									.oidc(Customizer.withDefaults())
					)
					.authorizeHttpRequests((authorize) ->
							authorize.anyRequest().authenticated()
					)
					.securityContext((securityContext) ->
							securityContext.securityContextRepository(securityContextRepository));
			// @formatter:on

			return http.build();
		}

	}

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
	static class AuthorizationServerConfiguration {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.oauth2AuthorizationServer((authorizationServer) ->
							authorizationServer
									.oidc(Customizer.withDefaults())
					)
					.authorizeHttpRequests((authorize) ->
							authorize.anyRequest().authenticated()
					);
			// @formatter:on

			return http.build();
		}

		@Bean
		RegisteredClientRepository registeredClientRepository() {
			RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
			return new InMemoryRegisteredClientRepository(registeredClient);
		}

		@Bean
		OAuth2AuthorizationService authorizationService() {
			return new InMemoryOAuth2AuthorizationService();
		}

		@Bean
		JWKSource<SecurityContext> jwkSource() {
			return new ImmutableJWKSet<>(new JWKSet(TestJwks.DEFAULT_RSA_JWK));
		}

		@Bean
		JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
			return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
		}

		@Bean
		JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
			return new NimbusJwtEncoder(jwkSource);
		}

		@Bean
		AuthorizationServerSettings authorizationServerSettings() {
			return AuthorizationServerSettings.builder().multipleIssuersAllowed(true).build();
		}

	}

}
