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

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;
import javax.annotation.PreDestroy;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.hamcrest.core.AllOf;
import org.hamcrest.core.StringContains;
import org.hamcrest.core.StringEndsWith;
import org.hamcrest.core.StringStartsWith;
import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.ApplicationContext;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.Environment;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenAttributes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestOperations;
import org.springframework.web.context.support.GenericWebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.core.StringStartsWith.startsWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.oauth2.core.TestOAuth2AccessTokens.noScopes;
import static org.springframework.security.oauth2.jwt.NimbusJwtDecoder.withJwkSetUri;
import static org.springframework.security.oauth2.jwt.NimbusJwtDecoder.withPublicKey;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.POST;

/**
 * Tests for {@link OAuth2ResourceServerConfigurer}
 *
 * @author Josh Cummings
 */
public class OAuth2ResourceServerConfigurerTests {
	private static final String JWT_TOKEN = "token";
	private static final String JWT_SUBJECT = "mock-test-subject";
	private static final Map<String, Object> JWT_HEADERS = Collections.singletonMap("alg", JwsAlgorithms.RS256);
	private static final Map<String, Object> JWT_CLAIMS = Collections.singletonMap(JwtClaimNames.SUB, JWT_SUBJECT);
	private static final Jwt JWT = new Jwt(JWT_TOKEN, Instant.MIN, Instant.MAX, JWT_HEADERS, JWT_CLAIMS);
	private static final String JWK_SET_URI = "https://mock.org";
	private static final JwtAuthenticationToken JWT_AUTHENTICATION_TOKEN =
			new JwtAuthenticationToken(JWT, Collections.emptyList());

	private static final String INTROSPECTION_URI = "https://idp.example.com";
	private static final String CLIENT_ID = "client-id";
	private static final String CLIENT_SECRET = "client-secret";
	private static final OAuth2IntrospectionAuthenticationToken INTROSPECTION_AUTHENTICATION_TOKEN =
			new OAuth2IntrospectionAuthenticationToken(noScopes(), new OAuth2TokenAttributes(JWT_CLAIMS), Collections.emptyList());

	@Autowired(required = false)
	MockMvc mvc;

	@Autowired(required = false)
	MockWebServer web;

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Test
	public void getWhenUsingDefaultsWithValidBearerTokenThenAcceptsRequest()
			throws Exception {

		this.spring.register(RestOperationsConfig.class, DefaultConfig.class, BasicController.class).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("ValidNoScopes");

		this.mvc.perform(get("/").with(bearerToken(token)))
				.andExpect(status().isOk())
				.andExpect(content().string("ok"));
	}

	@Test
	public void getWhenUsingDefaultsInLambdaWithValidBearerTokenThenAcceptsRequest()
			throws Exception {

		this.spring.register(RestOperationsConfig.class, DefaultInLambdaConfig.class, BasicController.class).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("ValidNoScopes");

		this.mvc.perform(get("/").with(bearerToken(token)))
				.andExpect(status().isOk())
				.andExpect(content().string("ok"));
	}

	@Test
	public void getWhenUsingJwkSetUriThenAcceptsRequest() throws Exception {
		this.spring.register(WebServerConfig.class, JwkSetUriConfig.class, BasicController.class).autowire();
		mockWebServer(jwks("Default"));
		String token = this.token("ValidNoScopes");

		this.mvc.perform(get("/").with(bearerToken(token)))
				.andExpect(status().isOk())
				.andExpect(content().string("ok"));
	}

	@Test
	public void getWhenUsingJwkSetUriInLambdaThenAcceptsRequest() throws Exception {
		this.spring.register(WebServerConfig.class, JwkSetUriInLambdaConfig.class, BasicController.class).autowire();
		mockWebServer(jwks("Default"));
		String token = this.token("ValidNoScopes");

		this.mvc.perform(get("/").with(bearerToken(token)))
				.andExpect(status().isOk())
				.andExpect(content().string("ok"));
	}

	@Test
	public void getWhenUsingDefaultsWithExpiredBearerTokenThenInvalidToken()
			throws Exception {

		this.spring.register(RestOperationsConfig.class, DefaultConfig.class, BasicController.class).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("Expired");

		this.mvc.perform(get("/").with(bearerToken(token)))
				.andExpect(status().isUnauthorized())
				.andExpect(invalidTokenHeader("An error occurred while attempting to decode the Jwt"));
	}

	@Test
	public void getWhenUsingDefaultsWithBadJwkEndpointThenInvalidToken()
		throws Exception {

		this.spring.register(RestOperationsConfig.class, DefaultConfig.class).autowire();
		mockRestOperations("malformed");
		String token = this.token("ValidNoScopes");

		this.mvc.perform(get("/").with(bearerToken(token)))
				.andExpect(status().isUnauthorized())
				.andExpect(invalidTokenHeader("An error occurred while attempting to decode the Jwt: Malformed Jwk set"));
	}

	@Test
	public void getWhenUsingDefaultsWithUnavailableJwkEndpointThenInvalidToken()
			throws Exception {

		this.spring.register(WebServerConfig.class, JwkSetUriConfig.class).autowire();
		this.web.shutdown();
		String token = this.token("ValidNoScopes");

		this.mvc.perform(get("/").with(bearerToken(token)))
				.andExpect(status().isUnauthorized())
				.andExpect(invalidTokenHeader("An error occurred while attempting to decode the Jwt"));
	}

	@Test
	public void getWhenUsingDefaultsWithMalformedBearerTokenThenInvalidToken()
			throws Exception {

		this.spring.register(JwkSetUriConfig.class).autowire();

		this.mvc.perform(get("/").with(bearerToken("an\"invalid\"token")))
				.andExpect(status().isUnauthorized())
				.andExpect(invalidTokenHeader("Bearer token is malformed"));
	}

	@Test
	public void getWhenUsingDefaultsWithMalformedPayloadThenInvalidToken()
			throws Exception {

		this.spring.register(RestOperationsConfig.class, DefaultConfig.class).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("MalformedPayload");

		this.mvc.perform(get("/").with(bearerToken(token)))
				.andExpect(status().isUnauthorized())
				.andExpect(invalidTokenHeader("An error occurred while attempting to decode the Jwt: Malformed payload"));
	}

	@Test
	public void getWhenUsingDefaultsWithUnsignedBearerTokenThenInvalidToken()
			throws Exception {

		this.spring.register(JwkSetUriConfig.class).autowire();
		String token = this.token("Unsigned");

		this.mvc.perform(get("/").with(bearerToken(token)))
				.andExpect(status().isUnauthorized())
				.andExpect(invalidTokenHeader("Unsupported algorithm of none"));
	}

	@Test
	public void getWhenUsingDefaultsWithBearerTokenBeforeNotBeforeThenInvalidToken()
			throws Exception {

		this.spring.register(RestOperationsConfig.class, DefaultConfig.class).autowire();
		this.mockRestOperations(jwks("Default"));
		String token = this.token("TooEarly");

		this.mvc.perform(get("/").with(bearerToken(token)))
				.andExpect(status().isUnauthorized())
				.andExpect(invalidTokenHeader("An error occurred while attempting to decode the Jwt"));
	}

	@Test
	public void getWhenUsingDefaultsWithBearerTokenInTwoPlacesThenInvalidRequest()
			throws Exception {

		this.spring.register(JwkSetUriConfig.class).autowire();

		this.mvc.perform(get("/")
						.with(bearerToken("token"))
						.with(bearerToken("token").asParam()))
				.andExpect(status().isBadRequest())
				.andExpect(invalidRequestHeader("Found multiple bearer tokens in the request"));
	}

	@Test
	public void getWhenUsingDefaultsWithBearerTokenInTwoParametersThenInvalidRequest()
			throws Exception {

		this.spring.register(JwkSetUriConfig.class).autowire();

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("access_token", "token1");
		params.add("access_token", "token2");

		this.mvc.perform(get("/")
				.params(params))
				.andExpect(status().isBadRequest())
				.andExpect(invalidRequestHeader("Found multiple bearer tokens in the request"));
	}

	@Test
	public void postWhenUsingDefaultsWithBearerTokenAsFormParameterThenIgnoresToken()
			throws Exception {

		this.spring.register(JwkSetUriConfig.class).autowire();

		this.mvc.perform(post("/") // engage csrf
				.with(bearerToken("token").asParam()))
				.andExpect(status().isForbidden())
				.andExpect(header().doesNotExist(HttpHeaders.WWW_AUTHENTICATE));
	}

	@Test
	public void postWhenCsrfDisabledWithBearerTokenAsFormParameterThenIgnoresToken()
			throws Exception {

		this.spring.register(CsrfDisabledConfig.class).autowire();

		this.mvc.perform(post("/")
				.with(bearerToken("token").asParam()))
				.andExpect(status().isUnauthorized())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer"));
	}

	@Test
	public void getWhenUsingDefaultsWithNoBearerTokenThenUnauthorized()
			throws Exception {

		this.spring.register(JwkSetUriConfig.class).autowire();

		this.mvc.perform(get("/"))
				.andExpect(status().isUnauthorized())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer"));
	}

	@Test
	public void getWhenUsingDefaultsWithSufficientlyScopedBearerTokenThenAcceptsRequest()
			throws Exception {

		this.spring.register(RestOperationsConfig.class, DefaultConfig.class, BasicController.class).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("ValidMessageReadScope");

		this.mvc.perform(get("/requires-read-scope")
				.with(bearerToken(token)))
				.andExpect(status().isOk())
				.andExpect(content().string("SCOPE_message:read"));
	}

	@Test
	public void getWhenUsingDefaultsWithInsufficientScopeThenInsufficientScopeError()
			throws Exception {

		this.spring.register(RestOperationsConfig.class, DefaultConfig.class, BasicController.class).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("ValidNoScopes");

		this.mvc.perform(get("/requires-read-scope")
				.with(bearerToken(token)))
				.andExpect(status().isForbidden())
				.andExpect(insufficientScopeHeader());
	}

	@Test
	public void getWhenUsingDefaultsWithInsufficientScpThenInsufficientScopeError()
			throws Exception {

		this.spring.register(RestOperationsConfig.class, DefaultConfig.class, BasicController.class).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("ValidMessageWriteScp");

		this.mvc.perform(get("/requires-read-scope")
				.with(bearerToken(token)))
				.andExpect(status().isForbidden())
				.andExpect(insufficientScopeHeader());
	}

	@Test
	public void getWhenUsingDefaultsAndAuthorizationServerHasNoMatchingKeyThenInvalidToken()
			throws Exception {

		this.spring.register(RestOperationsConfig.class, DefaultConfig.class).autowire();
		mockRestOperations(jwks("Empty"));
		String token = this.token("ValidNoScopes");

		this.mvc.perform(get("/")
				.with(bearerToken(token)))
				.andExpect(status().isUnauthorized())
				.andExpect(invalidTokenHeader("An error occurred while attempting to decode the Jwt"));
	}

	@Test
	public void getWhenUsingDefaultsAndAuthorizationServerHasMultipleMatchingKeysThenOk()
			throws Exception {

		this.spring.register(RestOperationsConfig.class, DefaultConfig.class, BasicController.class).autowire();
		mockRestOperations(jwks("TwoKeys"));
		String token = this.token("ValidNoScopes");

		this.mvc.perform(get("/authenticated")
				.with(bearerToken(token)))
				.andExpect(status().isOk())
				.andExpect(content().string("test-subject"));
	}

	@Test
	public void getWhenUsingDefaultsAndKeyMatchesByKidThenOk()
			throws Exception {

		this.spring.register(RestOperationsConfig.class, DefaultConfig.class, BasicController.class).autowire();
		mockRestOperations(jwks("TwoKeys"));
		String token = this.token("Kid");

		this.mvc.perform(get("/authenticated")
				.with(bearerToken(token)))
				.andExpect(status().isOk())
				.andExpect(content().string("test-subject"));
	}

	// -- Method Security

	@Test
	public void getWhenUsingMethodSecurityWithValidBearerTokenThenAcceptsRequest()
			throws Exception {

		this.spring.register(RestOperationsConfig.class, MethodSecurityConfig.class, BasicController.class).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("ValidMessageReadScope");

		this.mvc.perform(get("/ms-requires-read-scope")
				.with(bearerToken(token)))
				.andExpect(status().isOk())
				.andExpect(content().string("SCOPE_message:read"));
	}

	@Test
	public void getWhenUsingMethodSecurityWithValidBearerTokenHavingScpAttributeThenAcceptsRequest()
			throws Exception {

		this.spring.register(RestOperationsConfig.class, MethodSecurityConfig.class, BasicController.class).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("ValidMessageReadScp");

		this.mvc.perform(get("/ms-requires-read-scope")
				.with(bearerToken(token)))
				.andExpect(status().isOk())
				.andExpect(content().string("SCOPE_message:read"));
	}

	@Test
	public void getWhenUsingMethodSecurityWithInsufficientScopeThenInsufficientScopeError()
			throws Exception {

		this.spring.register(RestOperationsConfig.class, MethodSecurityConfig.class, BasicController.class).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("ValidNoScopes");

		this.mvc.perform(get("/ms-requires-read-scope")
				.with(bearerToken(token)))
				.andExpect(status().isForbidden())
				.andExpect(insufficientScopeHeader());

	}

	@Test
	public void getWhenUsingMethodSecurityWithInsufficientScpThenInsufficientScopeError()
			throws Exception {

		this.spring.register(RestOperationsConfig.class, MethodSecurityConfig.class, BasicController.class).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("ValidMessageWriteScp");

		this.mvc.perform(get("/ms-requires-read-scope")
				.with(bearerToken(token)))
				.andExpect(status().isForbidden())
				.andExpect(insufficientScopeHeader());
	}

	@Test
	public void getWhenUsingMethodSecurityWithDenyAllThenInsufficientScopeError()
			throws Exception {

		this.spring.register(RestOperationsConfig.class, MethodSecurityConfig.class, BasicController.class).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("ValidMessageReadScope");

		this.mvc.perform(get("/ms-deny")
				.with(bearerToken(token)))
				.andExpect(status().isForbidden())
				.andExpect(insufficientScopeHeader());
	}

	// -- Resource Server should not engage csrf

	@Test
	public void postWhenUsingDefaultsWithValidBearerTokenAndNoCsrfTokenThenOk()
			throws Exception {

		this.spring.register(RestOperationsConfig.class, DefaultConfig.class, BasicController.class).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("ValidNoScopes");

		this.mvc.perform(post("/authenticated")
				.with(bearerToken(token)))
				.andExpect(status().isOk())
				.andExpect(content().string("test-subject"));
	}

	@Test
	public void postWhenUsingDefaultsWithNoBearerTokenThenCsrfDenies()
			throws Exception {

		this.spring.register(JwkSetUriConfig.class).autowire();

		this.mvc.perform(post("/authenticated"))
				.andExpect(status().isForbidden())
				.andExpect(header().doesNotExist(HttpHeaders.WWW_AUTHENTICATE));
	}

	@Test
	public void postWhenUsingDefaultsWithExpiredBearerTokenAndNoCsrfThenInvalidToken()
			throws Exception {

		this.spring.register(RestOperationsConfig.class, DefaultConfig.class).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("Expired");

		this.mvc.perform(post("/authenticated")
				.with(bearerToken(token)))
				.andExpect(status().isUnauthorized())
				.andExpect(invalidTokenHeader("An error occurred while attempting to decode the Jwt"));
	}

	// -- Resource Server should not create sessions

	@Test
	public void requestWhenDefaultConfiguredThenSessionIsNotCreated()
			throws Exception {

		this.spring.register(RestOperationsConfig.class, DefaultConfig.class, BasicController.class).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("ValidNoScopes");

		MvcResult result = this.mvc.perform(get("/")
				.with(bearerToken(token)))
				.andExpect(status().isOk())
				.andReturn();

		assertThat(result.getRequest().getSession(false)).isNull();
	}

	@Test
	public void requestWhenIntrospectionConfiguredThenSessionIsNotCreated()
			throws Exception {

		this.spring.register(RestOperationsConfig.class, OpaqueTokenConfig.class, BasicController.class).autowire();
		mockRestOperations(json("Active"));

		MvcResult result = this.mvc.perform(get("/authenticated")
				.with(bearerToken("token")))
				.andExpect(status().isOk())
				.andExpect(content().string("test-subject"))
				.andReturn();

		assertThat(result.getRequest().getSession(false)).isNull();
	}

	@Test
	public void requestWhenUsingDefaultsAndNoBearerTokenThenSessionIsCreated()
			throws Exception {

		this.spring.register(JwkSetUriConfig.class, BasicController.class).autowire();

		MvcResult result = this.mvc.perform(get("/"))
				.andExpect(status().isUnauthorized())
				.andReturn();

		assertThat(result.getRequest().getSession(false)).isNotNull();
	}

	@Test
	public void requestWhenSessionManagementConfiguredThenUserConfigurationOverrides()
			throws Exception {

		this.spring.register(RestOperationsConfig.class, AlwaysSessionCreationConfig.class, BasicController.class).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("ValidNoScopes");

		MvcResult result = this.mvc.perform(get("/")
				.with(bearerToken(token)))
				.andExpect(status().isOk())
				.andReturn();

		assertThat(result.getRequest().getSession(false)).isNotNull();
	}

	// -- custom bearer token resolver

	@Test
	public void requestWhenBearerTokenResolverAllowsRequestBodyThenEitherHeaderOrRequestBodyIsAccepted()
			throws Exception {

		this.spring.register(AllowBearerTokenInRequestBodyConfig.class, JwtDecoderConfig.class,
				BasicController.class).autowire();

		JwtDecoder decoder = this.spring.getContext().getBean(JwtDecoder.class);
		when(decoder.decode(anyString())).thenReturn(JWT);

		this.mvc.perform(get("/authenticated")
				.with(bearerToken(JWT_TOKEN)))
				.andExpect(status().isOk())
				.andExpect(content().string(JWT_SUBJECT));

		this.mvc.perform(post("/authenticated")
				.param("access_token", JWT_TOKEN))
				.andExpect(status().isOk())
				.andExpect(content().string(JWT_SUBJECT));
	}

	@Test
	public void requestWhenBearerTokenResolverAllowsQueryParameterThenEitherHeaderOrQueryParameterIsAccepted()
			throws Exception {

		this.spring.register(AllowBearerTokenAsQueryParameterConfig.class, JwtDecoderConfig.class,
				BasicController.class).autowire();

		JwtDecoder decoder = this.spring.getContext().getBean(JwtDecoder.class);
		when(decoder.decode(anyString())).thenReturn(JWT);

		this.mvc.perform(get("/authenticated")
				.with(bearerToken(JWT_TOKEN)))
				.andExpect(status().isOk())
				.andExpect(content().string(JWT_SUBJECT));

		this.mvc.perform(get("/authenticated")
				.param("access_token", JWT_TOKEN))
				.andExpect(status().isOk())
				.andExpect(content().string(JWT_SUBJECT));
	}

	@Test
	public void requestWhenBearerTokenResolverAllowsRequestBodyAndRequestContainsTwoTokensThenInvalidRequest()
			throws Exception {

		this.spring.register(AllowBearerTokenInRequestBodyConfig.class, JwtDecoderConfig.class,
				BasicController.class).autowire();

		JwtDecoder decoder = this.spring.getContext().getBean(JwtDecoder.class);
		when(decoder.decode(anyString())).thenReturn(JWT);

		this.mvc.perform(post("/authenticated")
				.param("access_token", JWT_TOKEN)
				.with(bearerToken(JWT_TOKEN))
				.with(csrf()))
				.andExpect(status().isBadRequest())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("invalid_request")));
	}

	@Test
	public void requestWhenBearerTokenResolverAllowsQueryParameterAndRequestContainsTwoTokensThenInvalidRequest()
			throws Exception {

		this.spring.register(AllowBearerTokenAsQueryParameterConfig.class, JwtDecoderConfig.class,
				BasicController.class).autowire();

		JwtDecoder decoder = this.spring.getContext().getBean(JwtDecoder.class);
		when(decoder.decode(anyString())).thenReturn(JWT);

		this.mvc.perform(get("/authenticated")
				.with(bearerToken(JWT_TOKEN))
				.param("access_token", JWT_TOKEN))
				.andExpect(status().isBadRequest())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("invalid_request")));
	}

	@Test
	public void getBearerTokenResolverWhenDuplicateResolverBeansAndAnotherOnTheDslThenTheDslOneIsUsed() {
		BearerTokenResolver resolverBean = mock(BearerTokenResolver.class);
		BearerTokenResolver resolver = mock(BearerTokenResolver.class);

		GenericWebApplicationContext context = new GenericWebApplicationContext();
		context.registerBean("resolverOne", BearerTokenResolver.class, () -> resolverBean);
		context.registerBean("resolverTwo", BearerTokenResolver.class, () -> resolverBean);
		this.spring.context(context).autowire();

		OAuth2ResourceServerConfigurer oauth2 = new OAuth2ResourceServerConfigurer(context);

		oauth2.bearerTokenResolver(resolver);

		assertThat(oauth2.getBearerTokenResolver()).isEqualTo(resolver);
	}

	@Test
	public void getBearerTokenResolverWhenDuplicateResolverBeansThenWiringException() {
		assertThatCode(() -> this.spring.register(MultipleBearerTokenResolverBeansConfig.class).autowire())
				.isInstanceOf(BeanCreationException.class)
				.hasRootCauseInstanceOf(NoUniqueBeanDefinitionException.class);
	}

	@Test
	public void getBearerTokenResolverWhenResolverBeanAndAnotherOnTheDslThenTheDslOneIsUsed() {
		BearerTokenResolver resolver = mock(BearerTokenResolver.class);
		BearerTokenResolver resolverBean = mock(BearerTokenResolver.class);

		GenericWebApplicationContext context = new GenericWebApplicationContext();
		context.registerBean(BearerTokenResolver.class, () -> resolverBean);
		this.spring.context(context).autowire();

		OAuth2ResourceServerConfigurer oauth2 = new OAuth2ResourceServerConfigurer(context);
		oauth2.bearerTokenResolver(resolver);

		assertThat(oauth2.getBearerTokenResolver()).isEqualTo(resolver);
	}

	@Test
	public void getBearerTokenResolverWhenNoResolverSpecifiedThenTheDefaultIsUsed() {
		ApplicationContext context =
				this.spring.context(new GenericWebApplicationContext()).getContext();

		OAuth2ResourceServerConfigurer oauth2 = new OAuth2ResourceServerConfigurer(context);

		assertThat(oauth2.getBearerTokenResolver()).isInstanceOf(DefaultBearerTokenResolver.class);
	}

	// -- custom jwt decoder

	@Test
	public void requestWhenCustomJwtDecoderWiredOnDslThenUsed()
			throws Exception {

		this.spring.register(CustomJwtDecoderOnDsl.class, BasicController.class).autowire();

		CustomJwtDecoderOnDsl config = this.spring.getContext().getBean(CustomJwtDecoderOnDsl.class);
		JwtDecoder decoder = config.decoder();

		when(decoder.decode(anyString())).thenReturn(JWT);

		this.mvc.perform(get("/authenticated")
				.with(bearerToken(JWT_TOKEN)))
				.andExpect(status().isOk())
				.andExpect(content().string(JWT_SUBJECT));
	}

	@Test
	public void requestWhenCustomJwtDecoderInLambdaOnDslThenUsed()
			throws Exception {

		this.spring.register(CustomJwtDecoderInLambdaOnDsl.class, BasicController.class).autowire();

		CustomJwtDecoderInLambdaOnDsl config = this.spring.getContext().getBean(CustomJwtDecoderInLambdaOnDsl.class);
		JwtDecoder decoder = config.decoder();

		when(decoder.decode(anyString())).thenReturn(JWT);

		this.mvc.perform(get("/authenticated")
				.with(bearerToken(JWT_TOKEN)))
				.andExpect(status().isOk())
				.andExpect(content().string(JWT_SUBJECT));
	}

	@Test
	public void requestWhenCustomJwtDecoderExposedAsBeanThenUsed()
			throws Exception {

		this.spring.register(CustomJwtDecoderAsBean.class, BasicController.class).autowire();

		JwtDecoder decoder = this.spring.getContext().getBean(JwtDecoder.class);

		when(decoder.decode(anyString())).thenReturn(JWT);

		this.mvc.perform(get("/authenticated")
				.with(bearerToken(JWT_TOKEN)))
				.andExpect(status().isOk())
				.andExpect(content().string(JWT_SUBJECT));
	}

	@Test
	public void getJwtDecoderWhenConfiguredWithDecoderAndJwkSetUriThenLastOneWins() {
		ApplicationContext context = mock(ApplicationContext.class);

		OAuth2ResourceServerConfigurer.JwtConfigurer jwtConfigurer =
				new OAuth2ResourceServerConfigurer(context).jwt();

		JwtDecoder decoder = mock(JwtDecoder.class);

		jwtConfigurer.jwkSetUri(JWK_SET_URI);
		jwtConfigurer.decoder(decoder);

		assertThat(jwtConfigurer.getJwtDecoder()).isEqualTo(decoder);

		jwtConfigurer =
				new OAuth2ResourceServerConfigurer(context).jwt();

		jwtConfigurer.decoder(decoder);
		jwtConfigurer.jwkSetUri(JWK_SET_URI);

		assertThat(jwtConfigurer.getJwtDecoder()).isInstanceOf(NimbusJwtDecoder.class);

	}

	@Test
	public void getJwtDecoderWhenConflictingJwtDecodersThenTheDslWiredOneTakesPrecedence() {

		JwtDecoder decoderBean = mock(JwtDecoder.class);
		JwtDecoder decoder = mock(JwtDecoder.class);

		ApplicationContext context = mock(ApplicationContext.class);
		when(context.getBean(JwtDecoder.class)).thenReturn(decoderBean);

		OAuth2ResourceServerConfigurer.JwtConfigurer jwtConfigurer =
				new OAuth2ResourceServerConfigurer(context).jwt();
		jwtConfigurer.decoder(decoder);

		assertThat(jwtConfigurer.getJwtDecoder()).isEqualTo(decoder);
	}

	@Test
	public void getJwtDecoderWhenContextHasBeanAndUserConfiguresJwkSetUriThenJwkSetUriTakesPrecedence() {

		JwtDecoder decoder = mock(JwtDecoder.class);
		ApplicationContext context = mock(ApplicationContext.class);
		when(context.getBean(JwtDecoder.class)).thenReturn(decoder);

		OAuth2ResourceServerConfigurer.JwtConfigurer jwtConfigurer =
				new OAuth2ResourceServerConfigurer(context).jwt();

		jwtConfigurer.jwkSetUri(JWK_SET_URI);

		assertThat(jwtConfigurer.getJwtDecoder()).isNotEqualTo(decoder);
		assertThat(jwtConfigurer.getJwtDecoder()).isInstanceOf(NimbusJwtDecoder.class);
	}

	@Test
	public void getJwtDecoderWhenTwoJwtDecoderBeansAndAnotherWiredOnDslThenDslWiredOneTakesPrecedence() {

		JwtDecoder decoderBean = mock(JwtDecoder.class);
		JwtDecoder decoder = mock(JwtDecoder.class);

		GenericWebApplicationContext context = new GenericWebApplicationContext();
		context.registerBean("decoderOne", JwtDecoder.class, () -> decoderBean);
		context.registerBean("decoderTwo", JwtDecoder.class, () -> decoderBean);
		this.spring.context(context).autowire();

		OAuth2ResourceServerConfigurer.JwtConfigurer jwtConfigurer =
				new OAuth2ResourceServerConfigurer(context).jwt();
		jwtConfigurer.decoder(decoder);

		assertThat(jwtConfigurer.getJwtDecoder()).isEqualTo(decoder);
	}

	@Test
	public void getJwtDecoderWhenTwoJwtDecoderBeansThenThrowsException() {

		JwtDecoder decoder = mock(JwtDecoder.class);
		GenericWebApplicationContext context = new GenericWebApplicationContext();
		context.registerBean("decoderOne", JwtDecoder.class, () -> decoder);
		context.registerBean("decoderTwo", JwtDecoder.class, () -> decoder);

		this.spring.context(context).autowire();

		OAuth2ResourceServerConfigurer.JwtConfigurer jwtConfigurer =
				new OAuth2ResourceServerConfigurer(context).jwt();

		assertThatCode(() -> jwtConfigurer.getJwtDecoder())
				.isInstanceOf(NoUniqueBeanDefinitionException.class);
	}

	// -- exception handling

	@Test
	public void requestWhenRealmNameConfiguredThenUsesOnUnauthenticated()
			throws Exception {

		this.spring.register(RealmNameConfiguredOnEntryPoint.class, JwtDecoderConfig.class).autowire();

		JwtDecoder decoder = this.spring.getContext().getBean(JwtDecoder.class);
		when(decoder.decode(anyString())).thenThrow(JwtException.class);

		this.mvc.perform(get("/authenticated")
				.with(bearerToken("invalid_token")))
				.andExpect(status().isUnauthorized())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, startsWith("Bearer realm=\"myRealm\"")));
	}

	@Test
	public void requestWhenRealmNameConfiguredThenUsesOnAccessDenied()
			throws Exception {

		this.spring.register(RealmNameConfiguredOnAccessDeniedHandler.class, JwtDecoderConfig.class).autowire();

		JwtDecoder decoder = this.spring.getContext().getBean(JwtDecoder.class);
		when(decoder.decode(anyString())).thenReturn(JWT);

		this.mvc.perform(get("/authenticated")
				.with(bearerToken("insufficiently_scoped")))
				.andExpect(status().isForbidden())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, startsWith("Bearer realm=\"myRealm\"")));
	}

	@Test
	public void authenticationEntryPointWhenGivenNullThenThrowsException() {
		ApplicationContext context = mock(ApplicationContext.class);
		OAuth2ResourceServerConfigurer configurer = new OAuth2ResourceServerConfigurer(context);
		assertThatCode(() -> configurer.authenticationEntryPoint(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void accessDeniedHandlerWhenGivenNullThenThrowsException() {
		ApplicationContext context = mock(ApplicationContext.class);
		OAuth2ResourceServerConfigurer configurer = new OAuth2ResourceServerConfigurer(context);
		assertThatCode(() -> configurer.accessDeniedHandler(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	// -- token validator

	@Test
	public void requestWhenCustomJwtValidatorFailsThenCorrespondingErrorMessage()
		throws Exception {

		this.spring.register(RestOperationsConfig.class, CustomJwtValidatorConfig.class).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("ValidNoScopes");

		OAuth2TokenValidator<Jwt> jwtValidator =
				this.spring.getContext().getBean(CustomJwtValidatorConfig.class)
						.getJwtValidator();

		OAuth2Error error = new OAuth2Error("custom-error", "custom-description", "custom-uri");

		when(jwtValidator.validate(any(Jwt.class))).thenReturn(OAuth2TokenValidatorResult.failure(error));

		this.mvc.perform(get("/")
				.with(bearerToken(token)))
				.andExpect(status().isUnauthorized())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("custom-description")));
	}

	@Test
	public void requestWhenClockSkewSetThenTimestampWindowRelaxedAccordingly()
		throws Exception {

		this.spring.register(RestOperationsConfig.class, UnexpiredJwtClockSkewConfig.class, BasicController.class).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("ExpiresAt4687177990");

		this.mvc.perform(get("/")
				.with(bearerToken(token)))
				.andExpect(status().isOk());
	}

	@Test
	public void requestWhenClockSkewSetButJwtStillTooLateThenReportsExpired()
			throws Exception {

		this.spring.register(RestOperationsConfig.class, ExpiredJwtClockSkewConfig.class, BasicController.class).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("ExpiresAt4687177990");

		this.mvc.perform(get("/")
				.with(bearerToken(token)))
				.andExpect(status().isUnauthorized())
				.andExpect(invalidTokenHeader("Jwt expired at"));
	}

	// -- converter

	@Test
	public void requestWhenJwtAuthenticationConverterConfiguredOnDslThenIsUsed()
			throws Exception {

		this.spring.register(JwtDecoderConfig.class, JwtAuthenticationConverterConfiguredOnDsl.class,
				BasicController.class).autowire();

		Converter<Jwt, JwtAuthenticationToken> jwtAuthenticationConverter =
				this.spring.getContext().getBean(JwtAuthenticationConverterConfiguredOnDsl.class)
						.getJwtAuthenticationConverter();
		when(jwtAuthenticationConverter.convert(JWT)).thenReturn(JWT_AUTHENTICATION_TOKEN);

		JwtDecoder jwtDecoder = this.spring.getContext().getBean(JwtDecoder.class);
		when(jwtDecoder.decode(anyString())).thenReturn(JWT);

		this.mvc.perform(get("/")
				.with(bearerToken(JWT_TOKEN)))
				.andExpect(status().isOk());

		verify(jwtAuthenticationConverter).convert(JWT);
	}

	@Test
	public void requestWhenJwtAuthenticationConverterCustomizedAuthoritiesThenThoseAuthoritiesArePropagated()
			throws Exception {

		this.spring.register(JwtDecoderConfig.class, CustomAuthorityMappingConfig.class, BasicController.class)
				.autowire();

		JwtDecoder decoder = this.spring.getContext().getBean(JwtDecoder.class);
		when(decoder.decode(JWT_TOKEN)).thenReturn(JWT);

		this.mvc.perform(get("/requires-read-scope")
				.with(bearerToken(JWT_TOKEN)))
				.andExpect(status().isOk());
	}

	// -- single key

	@Test
	public void requestWhenUsingPublicKeyAndValidTokenThenAuthenticates()
			throws Exception {

		this.spring.register(SingleKeyConfig.class, BasicController.class).autowire();
		String token = this.token("ValidNoScopes");

		this.mvc.perform(get("/")
				.with(bearerToken(token)))
				.andExpect(status().isOk());
	}

	@Test
	public void requestWhenUsingPublicKeyAndSignatureFailsThenReturnsInvalidToken()
			throws Exception {

		this.spring.register(SingleKeyConfig.class).autowire();
		String token = this.token("WrongSignature");

		this.mvc.perform(get("/")
				.with(bearerToken(token)))
				.andExpect(invalidTokenHeader("signature"));
	}

	@Test
	public void requestWhenUsingPublicKeyAlgorithmDoesNotMatchThenReturnsInvalidToken()
			throws Exception {

		this.spring.register(SingleKeyConfig.class).autowire();
		String token = this.token("WrongAlgorithm");

		this.mvc.perform(get("/")
				.with(bearerToken(token)))
				.andExpect(invalidTokenHeader("algorithm"));
	}

	@Test
	public void getWhenCustomJwtAuthenticationManagerThenUsed() throws Exception {
		this.spring.register(JwtAuthenticationManagerConfig.class, BasicController.class).autowire();

		when(bean(AuthenticationProvider.class).authenticate(any(Authentication.class)))
				.thenReturn(JWT_AUTHENTICATION_TOKEN);
		this.mvc.perform(get("/authenticated")
				.with(bearerToken("token")))
				.andExpect(status().isOk())
				.andExpect(content().string("mock-test-subject"));

		verifyBean(AuthenticationProvider.class).authenticate(any(Authentication.class));
	}

	// -- opaque


	@Test
	public void getWhenIntrospectingThenOk() throws Exception {
		this.spring.register(RestOperationsConfig.class, OpaqueTokenConfig.class, BasicController.class).autowire();
		mockRestOperations(json("Active"));

		this.mvc.perform(get("/authenticated")
				.with(bearerToken("token")))
				.andExpect(status().isOk())
				.andExpect(content().string("test-subject"));
	}

	@Test
	public void getWhenOpaqueTokenInLambdaAndIntrospectingThenOk() throws Exception {
		this.spring.register(RestOperationsConfig.class, OpaqueTokenInLambdaConfig.class, BasicController.class).autowire();
		mockRestOperations(json("Active"));

		this.mvc.perform(get("/authenticated")
				.with(bearerToken("token")))
				.andExpect(status().isOk())
				.andExpect(content().string("test-subject"));
	}

	@Test
	public void getWhenIntrospectionFailsThenUnauthorized() throws Exception {
		this.spring.register(RestOperationsConfig.class, OpaqueTokenConfig.class).autowire();
		mockRestOperations(json("Inactive"));

		this.mvc.perform(get("/")
				.with(bearerToken("token")))
				.andExpect(status().isUnauthorized())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE,
						containsString("Provided token [token] isn't active")));
	}

	@Test
	public void getWhenIntrospectionLacksScopeThenForbidden() throws Exception {
		this.spring.register(RestOperationsConfig.class, OpaqueTokenConfig.class).autowire();
		mockRestOperations(json("ActiveNoScopes"));

		this.mvc.perform(get("/requires-read-scope")
				.with(bearerToken("token")))
				.andExpect(status().isForbidden())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("scope")));
	}

	@Test
	public void getWhenCustomIntrospectionAuthenticationManagerThenUsed() throws Exception {
		this.spring.register(OpaqueTokenAuthenticationManagerConfig.class, BasicController.class).autowire();

		when(bean(AuthenticationProvider.class).authenticate(any(Authentication.class)))
				.thenReturn(INTROSPECTION_AUTHENTICATION_TOKEN);
		this.mvc.perform(get("/authenticated")
				.with(bearerToken("token")))
				.andExpect(status().isOk())
				.andExpect(content().string("mock-test-subject"));

		verifyBean(AuthenticationProvider.class).authenticate(any(Authentication.class));
	}

	@Test
	public void getWhenCustomIntrospectionAuthenticationManagerInLambdaThenUsed() throws Exception {
		this.spring.register(OpaqueTokenAuthenticationManagerInLambdaConfig.class, BasicController.class).autowire();

		when(bean(AuthenticationProvider.class).authenticate(any(Authentication.class)))
				.thenReturn(INTROSPECTION_AUTHENTICATION_TOKEN);
		this.mvc.perform(get("/authenticated")
				.with(bearerToken("token")))
				.andExpect(status().isOk())
				.andExpect(content().string("mock-test-subject"));

		verifyBean(AuthenticationProvider.class).authenticate(any(Authentication.class));
	}

	@Test
	public void configureWhenOnlyIntrospectionUrlThenException() throws Exception {
		assertThatCode(() -> this.spring.register(OpaqueTokenHalfConfiguredConfig.class).autowire())
				.isInstanceOf(BeanCreationException.class);
	}

	@Test
	public void getIntrospectionClientWhenConfiguredWithClientAndIntrospectionUriThenLastOneWins() {
		ApplicationContext context = mock(ApplicationContext.class);

		OAuth2ResourceServerConfigurer.OpaqueTokenConfigurer opaqueTokenConfigurer =
				new OAuth2ResourceServerConfigurer(context).opaqueToken();

		OpaqueTokenIntrospector client = mock(OpaqueTokenIntrospector.class);

		opaqueTokenConfigurer.introspectionUri(INTROSPECTION_URI);
		opaqueTokenConfigurer.introspectionClientCredentials(CLIENT_ID, CLIENT_SECRET);
		opaqueTokenConfigurer.introspector(client);

		assertThat(opaqueTokenConfigurer.getIntrospector()).isEqualTo(client);

		opaqueTokenConfigurer =
				new OAuth2ResourceServerConfigurer(context).opaqueToken();

		opaqueTokenConfigurer.introspector(client);
		opaqueTokenConfigurer.introspectionUri(INTROSPECTION_URI);
		opaqueTokenConfigurer.introspectionClientCredentials(CLIENT_ID, CLIENT_SECRET);

		assertThat(opaqueTokenConfigurer.getIntrospector())
				.isInstanceOf(NimbusOpaqueTokenIntrospector.class);

	}

	@Test
	public void getIntrospectionClientWhenDslAndBeanWiredThenDslTakesPrecedence() {
		GenericApplicationContext context = new GenericApplicationContext();
		registerMockBean(context, "introspectionClientOne", OpaqueTokenIntrospector.class);
		registerMockBean(context, "introspectionClientTwo", OpaqueTokenIntrospector.class);

		OAuth2ResourceServerConfigurer.OpaqueTokenConfigurer opaqueToken =
				new OAuth2ResourceServerConfigurer(context).opaqueToken();
		opaqueToken.introspectionUri(INTROSPECTION_URI);
		opaqueToken.introspectionClientCredentials(CLIENT_ID, CLIENT_SECRET);

		assertThat(opaqueToken.getIntrospector()).isNotNull();
	}

	// -- In combination with other authentication providers

	@Test
	public void requestWhenBasicAndResourceServerEntryPointsThenMatchedByRequest()
			throws Exception {

		this.spring.register(BasicAndResourceServerConfig.class, JwtDecoderConfig.class).autowire();

		JwtDecoder decoder = this.spring.getContext().getBean(JwtDecoder.class);
		when(decoder.decode(anyString())).thenThrow(JwtException.class);

		this.mvc.perform(get("/authenticated")
				.with(httpBasic("some", "user")))
				.andExpect(status().isUnauthorized())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, startsWith("Basic")));

		this.mvc.perform(get("/authenticated"))
				.andExpect(status().isUnauthorized())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, startsWith("Basic")));

		this.mvc.perform(get("/authenticated")
				.with(bearerToken("invalid_token")))
				.andExpect(status().isUnauthorized())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, startsWith("Bearer")));
	}

	@Test
	public void requestWhenFormLoginAndResourceServerEntryPointsThenSessionCreatedByRequest()
			throws Exception {

		this.spring.register(FormAndResourceServerConfig.class, JwtDecoderConfig.class).autowire();

		JwtDecoder decoder = this.spring.getContext().getBean(JwtDecoder.class);
		when(decoder.decode(anyString())).thenThrow(JwtException.class);

		MvcResult result =
				this.mvc.perform(get("/authenticated"))
						.andExpect(status().isFound())
						.andExpect(redirectedUrl("http://localhost/login"))
						.andReturn();

		assertThat(result.getRequest().getSession(false)).isNotNull();

		result =
				this.mvc.perform(get("/authenticated")
						.with(bearerToken("token")))
						.andExpect(status().isUnauthorized())
						.andReturn();

		assertThat(result.getRequest().getSession(false)).isNull();
	}

	@Test
	public void requestWhenDefaultAndResourceServerAccessDeniedHandlersThenMatchedByRequest()
			throws Exception {

		this.spring.register(ExceptionHandlingAndResourceServerWithAccessDeniedHandlerConfig.class,
				JwtDecoderConfig.class).autowire();

		JwtDecoder decoder = this.spring.getContext().getBean(JwtDecoder.class);
		when(decoder.decode(anyString())).thenReturn(JWT);

		this.mvc.perform(get("/authenticated")
				.with(httpBasic("basic-user", "basic-password")))
				.andExpect(status().isForbidden())
				.andExpect(header().doesNotExist(HttpHeaders.WWW_AUTHENTICATE));

		this.mvc.perform(get("/authenticated")
				.with(bearerToken("insufficiently_scoped")))
				.andExpect(status().isForbidden())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, startsWith("Bearer")));
	}

	@Test
	public void getWhenAlsoUsingHttpBasicThenCorrectProviderEngages()
			throws Exception {

		this.spring.register(RestOperationsConfig.class, BasicAndResourceServerConfig.class, BasicController.class).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("ValidNoScopes");

		this.mvc.perform(get("/authenticated")
				.with(bearerToken(token)))
				.andExpect(status().isOk())
				.andExpect(content().string("test-subject"));

		this.mvc.perform(get("/authenticated")
				.with(httpBasic("basic-user", "basic-password")))
				.andExpect(status().isOk())
				.andExpect(content().string("basic-user"));
	}

	// -- authentication manager

	@Test
	public void getAuthenticationManagerWhenConfiguredAuthenticationManagerThenTakesPrecedence() {
		ApplicationContext context = mock(ApplicationContext.class);
		HttpSecurityBuilder http = mock(HttpSecurityBuilder.class);

		OAuth2ResourceServerConfigurer oauth2ResourceServer = new OAuth2ResourceServerConfigurer(context);
		AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
		oauth2ResourceServer
			.jwt()
				.authenticationManager(authenticationManager)
				.decoder(mock(JwtDecoder.class));
		assertThat(oauth2ResourceServer.getAuthenticationManager(http)).isSameAs(authenticationManager);

		oauth2ResourceServer = new OAuth2ResourceServerConfigurer(context);
		oauth2ResourceServer
			.opaqueToken()
				.authenticationManager(authenticationManager)
				.introspector(mock(OpaqueTokenIntrospector.class));
		assertThat(oauth2ResourceServer.getAuthenticationManager(http)).isSameAs(authenticationManager);
		verify(http, never()).authenticationProvider(any(AuthenticationProvider.class));
	}

	// -- Incorrect Configuration

	@Test
	public void configuredWhenMissingJwtAuthenticationProviderThenWiringException() {

		assertThatCode(() -> this.spring.register(JwtlessConfig.class).autowire())
				.isInstanceOf(BeanCreationException.class)
				.hasMessageContaining("neither was found");
	}

	@Test
	public void configureWhenMissingJwkSetUriThenWiringException() {

		assertThatCode(() -> this.spring.register(JwtHalfConfiguredConfig.class).autowire())
				.isInstanceOf(BeanCreationException.class)
				.hasMessageContaining("No qualifying bean of type");
	}

	@Test
	public void configureWhenUsingBothJwtAndOpaqueThenWiringException() {
		assertThatCode(() -> this.spring.register(OpaqueAndJwtConfig.class).autowire())
				.isInstanceOf(BeanCreationException.class)
				.hasMessageContaining("Spring Security only supports JWTs or Opaque Tokens");
	}

	// -- support

	@EnableWebSecurity
	static class DefaultConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.antMatchers("/requires-read-scope").access("hasAuthority('SCOPE_message:read')")
					.anyRequest().authenticated()
					.and()
				.oauth2ResourceServer()
					.jwt();
			// @formatter:on
		}
	}

	@EnableWebSecurity
	static class DefaultInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests(authorizeRequests ->
					authorizeRequests
						.antMatchers("/requires-read-scope").access("hasAuthority('SCOPE_message:read')")
						.anyRequest().authenticated()
				)
				.oauth2ResourceServer(oauth2ResourceServer ->
					oauth2ResourceServer
						.jwt(withDefaults())
				);
			// @formatter:on
		}
	}

	@EnableWebSecurity
	static class JwkSetUriConfig extends WebSecurityConfigurerAdapter {
		@Value("${mockwebserver.url:https://example.org}")
		String jwkSetUri;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.antMatchers("/requires-read-scope").access("hasAuthority('SCOPE_message:read')")
					.anyRequest().authenticated()
					.and()
				.oauth2ResourceServer()
					.jwt()
						.jwkSetUri(this.jwkSetUri);
			// @formatter:on
		}
	}

	@EnableWebSecurity
	static class JwkSetUriInLambdaConfig extends WebSecurityConfigurerAdapter {
		@Value("${mockwebserver.url:https://example.org}")
		String jwkSetUri;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests(authorizeRequests ->
					authorizeRequests
						.antMatchers("/requires-read-scope").access("hasAuthority('SCOPE_message:read')")
						.anyRequest().authenticated()
				)
				.oauth2ResourceServer(oauth2ResourceServer ->
					oauth2ResourceServer
						.jwt(jwt ->
							jwt
								.jwkSetUri(this.jwkSetUri)
						)
				);
			// @formatter:on
		}
	}

	@EnableWebSecurity
	static class CsrfDisabledConfig extends WebSecurityConfigurerAdapter {
		@Value("${mockwebserver.url:https://example.org}")
		String jwkSetUri;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.antMatchers("/requires-read-scope").access("hasAuthority('SCOPE_message:read')")
					.anyRequest().authenticated()
					.and()
				.csrf().disable()
				.oauth2ResourceServer()
					.jwt()
						.jwkSetUri(this.jwkSetUri);
			// @formatter:on
		}
	}

	@EnableWebSecurity
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	static class MethodSecurityConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.oauth2ResourceServer()
					.jwt();
			// @formatter:on
		}
	}

	@EnableWebSecurity
	static class JwtlessConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.oauth2ResourceServer();
			// @formatter:on
		}
	}

	@EnableWebSecurity
	static class RealmNameConfiguredOnEntryPoint extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.oauth2ResourceServer()
					.authenticationEntryPoint(authenticationEntryPoint())
					.jwt();
			// @formatter:on
		}

		AuthenticationEntryPoint authenticationEntryPoint() {
			BearerTokenAuthenticationEntryPoint entryPoint =
					new BearerTokenAuthenticationEntryPoint();
			entryPoint.setRealmName("myRealm");
			return entryPoint;
		}
	}

	@EnableWebSecurity
	static class RealmNameConfiguredOnAccessDeniedHandler extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().denyAll()
					.and()
				.oauth2ResourceServer()
					.accessDeniedHandler(accessDeniedHandler())
					.jwt();
			// @formatter:on
		}

		AccessDeniedHandler accessDeniedHandler() {
			BearerTokenAccessDeniedHandler accessDeniedHandler =
					new BearerTokenAccessDeniedHandler();
			accessDeniedHandler.setRealmName("myRealm");
			return accessDeniedHandler;
		}
	}

	@EnableWebSecurity
	static class ExceptionHandlingAndResourceServerWithAccessDeniedHandlerConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().denyAll()
					.and()
				.exceptionHandling()
					.defaultAccessDeniedHandlerFor(new AccessDeniedHandlerImpl(), request -> false)
					.and()
				.httpBasic()
					.and()
				.oauth2ResourceServer()
					.jwt();
			// @formatter:on
		}

		@Bean
		public UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(
					org.springframework.security.core.userdetails.User.withDefaultPasswordEncoder()
							.username("basic-user")
							.password("basic-password")
							.roles("USER")
							.build());
		}
	}

	@EnableWebSecurity
	static class JwtAuthenticationConverterConfiguredOnDsl extends WebSecurityConfigurerAdapter {
		private final Converter<Jwt, JwtAuthenticationToken> jwtAuthenticationConverter = mock(Converter.class);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off

			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.oauth2ResourceServer()
					.jwt()
						.jwtAuthenticationConverter(getJwtAuthenticationConverter());

			// @formatter:on
		}

		Converter<Jwt, JwtAuthenticationToken> getJwtAuthenticationConverter() {
			return this.jwtAuthenticationConverter;
		}
	}

	@EnableWebSecurity
	static class CustomAuthorityMappingConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off

			http
				.authorizeRequests()
					.antMatchers("/requires-read-scope").access("hasAuthority('message:read')")
					.and()
				.oauth2ResourceServer()
					.jwt()
						.jwtAuthenticationConverter(getJwtAuthenticationConverter());

			// @formatter:on
		}

		Converter<Jwt, AbstractAuthenticationToken> getJwtAuthenticationConverter() {
			JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
			converter.setJwtGrantedAuthoritiesConverter(jwt ->
					Collections.singletonList(new SimpleGrantedAuthority("message:read"))
			);
			return converter;
		}
	}

	@EnableWebSecurity
	static class BasicAndResourceServerConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.httpBasic()
					.and()
				.oauth2ResourceServer()
					.jwt();
			// @formatter:on
		}

		@Bean
		public UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(
					org.springframework.security.core.userdetails.User.withDefaultPasswordEncoder()
							.username("basic-user")
							.password("basic-password")
							.roles("USER")
							.build());
		}
	}

	@EnableWebSecurity
	static class FormAndResourceServerConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.formLogin()
					.and()
				.oauth2ResourceServer()
					.jwt();
			// @formatter:on
		}
	}

	@EnableWebSecurity
	static class JwtHalfConfiguredConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.oauth2ResourceServer()
					.jwt(); // missing key configuration, e.g. jwkSetUri
			// @formatter:on
		}
	}

	@EnableWebSecurity
	static class AlwaysSessionCreationConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
					.and()
				.oauth2ResourceServer()
					.jwt();
			// @formatter:on
		}
	}

	@EnableWebSecurity
	static class AllowBearerTokenInRequestBodyConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.oauth2ResourceServer()
					.bearerTokenResolver(allowRequestBody())
					.jwt();
			// @formatter:on
		}

		private BearerTokenResolver allowRequestBody() {
			DefaultBearerTokenResolver resolver = new DefaultBearerTokenResolver();
			resolver.setAllowFormEncodedBodyParameter(true);
			return resolver;
		}
	}

	@EnableWebSecurity
	static class AllowBearerTokenAsQueryParameterConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.oauth2ResourceServer()
					.jwt();
			// @formatter:on
		}

		@Bean
		BearerTokenResolver allowQueryParameter() {
			DefaultBearerTokenResolver resolver = new DefaultBearerTokenResolver();
			resolver.setAllowUriQueryParameter(true);
			return resolver;
		}
	}

	@EnableWebSecurity
	static class MultipleBearerTokenResolverBeansConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.oauth2ResourceServer()
					.jwt();
			// @formatter:on
		}

		@Bean
		BearerTokenResolver resolverOne() {
			DefaultBearerTokenResolver resolver = new DefaultBearerTokenResolver();
			resolver.setAllowUriQueryParameter(true);
			return resolver;
		}

		@Bean
		BearerTokenResolver resolverTwo() {
			DefaultBearerTokenResolver resolver = new DefaultBearerTokenResolver();
			resolver.setAllowFormEncodedBodyParameter(true);
			return resolver;
		}
	}

	@EnableWebSecurity
	static class CustomJwtDecoderOnDsl extends WebSecurityConfigurerAdapter {
		JwtDecoder decoder = mock(JwtDecoder.class);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.oauth2ResourceServer()
					.jwt()
						.decoder(decoder());
			// @formatter:on
		}

		JwtDecoder decoder() {
			return this.decoder;
		}
	}

	@EnableWebSecurity
	static class CustomJwtDecoderInLambdaOnDsl extends WebSecurityConfigurerAdapter {
		JwtDecoder decoder = mock(JwtDecoder.class);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests(authorizeRequests ->
					authorizeRequests
						.anyRequest().authenticated()
				)
				.oauth2ResourceServer(oauth2ResourceServer ->
					oauth2ResourceServer
						.jwt(jwt ->
							jwt
								.decoder(decoder())
						)
				);
			// @formatter:on
		}

		JwtDecoder decoder() {
			return this.decoder;
		}
	}

	@EnableWebSecurity
	static class CustomJwtDecoderAsBean extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.oauth2ResourceServer()
					.jwt();
			// @formatter:on
		}

		@Bean
		public JwtDecoder decoder() {
			return mock(JwtDecoder.class);
		}
	}

	@EnableWebSecurity
	static class JwtAuthenticationManagerConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.oauth2ResourceServer()
					.jwt()
						.authenticationManager(authenticationProvider()::authenticate);
			// @formatter:on
		}

		@Bean
		public AuthenticationProvider authenticationProvider() {
			return mock(AuthenticationProvider.class);
		}
	}

	@EnableWebSecurity
	static class CustomJwtValidatorConfig extends WebSecurityConfigurerAdapter {
		@Autowired
		NimbusJwtDecoder jwtDecoder;

		private final OAuth2TokenValidator<Jwt> jwtValidator = mock(OAuth2TokenValidator.class);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			this.jwtDecoder.setJwtValidator(this.jwtValidator);

			// @formatter:off
			http
				.oauth2ResourceServer()
					.jwt();
			// @formatter:on
		}

		public OAuth2TokenValidator<Jwt> getJwtValidator() {
			return this.jwtValidator;
		}
	}

	@EnableWebSecurity
	static class UnexpiredJwtClockSkewConfig extends WebSecurityConfigurerAdapter {
		@Autowired
		NimbusJwtDecoder jwtDecoder;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			Clock nearlyAnHourFromTokenExpiry =
					Clock.fixed(Instant.ofEpochMilli(4687181540000L), ZoneId.systemDefault());
			JwtTimestampValidator jwtValidator = new JwtTimestampValidator(Duration.ofHours(1));
			jwtValidator.setClock(nearlyAnHourFromTokenExpiry);

			this.jwtDecoder.setJwtValidator(jwtValidator);

			// @formatter:off
			http
				.oauth2ResourceServer()
					.jwt();
			// @formatter:on
		}
	}

	@EnableWebSecurity
	static class ExpiredJwtClockSkewConfig extends WebSecurityConfigurerAdapter {
		@Autowired
		NimbusJwtDecoder jwtDecoder;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			Clock justOverOneHourAfterExpiry =
					Clock.fixed(Instant.ofEpochMilli(4687181595000L), ZoneId.systemDefault());
			JwtTimestampValidator jwtValidator = new JwtTimestampValidator(Duration.ofHours(1));
			jwtValidator.setClock(justOverOneHourAfterExpiry);

			this.jwtDecoder.setJwtValidator(jwtValidator);

			// @formatter:off
			http
				.oauth2ResourceServer()
					.jwt();
		}
	}

	@EnableWebSecurity
	static class SingleKeyConfig extends WebSecurityConfigurerAdapter {
		byte[] spec = Base64.getDecoder().decode(
				"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoXJ8OyOv/eRnce4akdan" +
				"R4KYRfnC2zLV4uYNQpcFn6oHL0dj7D6kxQmsXoYgJV8ZVDn71KGmuLvolxsDncc2" +
				"UrhyMBY6DVQVgMSVYaPCTgW76iYEKGgzTEw5IBRQL9w3SRJWd3VJTZZQjkXef48O" +
				"cz06PGF3lhbz4t5UEZtdF4rIe7u+977QwHuh7yRPBQ3sII+cVoOUMgaXB9SHcGF2" +
				"iZCtPzL/IffDUcfhLQteGebhW8A6eUHgpD5A1PQ+JCw/G7UOzZAjjDjtNM2eqm8j" +
				"+Ms/gqnm4MiCZ4E+9pDN77CAAPVN7kuX6ejs9KBXpk01z48i9fORYk9u7rAkh1Hu" +
				"QwIDAQAB");

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.oauth2ResourceServer()
					.jwt();
			// @formatter:on
		}

		@Bean
		JwtDecoder decoder() throws Exception {
			RSAPublicKey publicKey = (RSAPublicKey)
					KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(this.spec));
			return withPublicKey(publicKey).build();
		}
	}

	@EnableWebSecurity
	static class OpaqueTokenConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.antMatchers("/requires-read-scope").hasAuthority("SCOPE_message:read")
					.anyRequest().authenticated()
					.and()
				.oauth2ResourceServer()
					.opaqueToken();
			// @formatter:on
		}
	}

	@EnableWebSecurity
	static class OpaqueTokenInLambdaConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests(authorizeRequests ->
					authorizeRequests
						.antMatchers("/requires-read-scope").hasAuthority("SCOPE_message:read")
						.anyRequest().authenticated()
				)
				.oauth2ResourceServer(oauth2ResourceServer ->
					oauth2ResourceServer
						.opaqueToken(withDefaults())
				);
			// @formatter:on
		}
	}

	@EnableWebSecurity
	static class OpaqueTokenAuthenticationManagerConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.oauth2ResourceServer()
					.opaqueToken()
						.authenticationManager(authenticationProvider()::authenticate);
			// @formatter:on
		}

		@Bean
		public AuthenticationProvider authenticationProvider() {
			return mock(AuthenticationProvider.class);
		}
	}

	@EnableWebSecurity
	static class OpaqueTokenAuthenticationManagerInLambdaConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests(authorizeRequests ->
					authorizeRequests
						.anyRequest().authenticated()
				)
				.oauth2ResourceServer(oauth2ResourceServer ->
					oauth2ResourceServer
						.opaqueToken(opaqueToken ->
							opaqueToken
								.authenticationManager(authenticationProvider()::authenticate)
						)
				);
			// @formatter:on
		}

		@Bean
		public AuthenticationProvider authenticationProvider() {
			return mock(AuthenticationProvider.class);
		}
	}

	@EnableWebSecurity
	static class OpaqueAndJwtConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.oauth2ResourceServer()
					.jwt()
						.and()
					.opaqueToken();
		}
	}

	@EnableWebSecurity
	static class OpaqueTokenHalfConfiguredConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.oauth2ResourceServer()
					.opaqueToken()
						.introspectionUri("https://idp.example.com"); // missing credentials
			// @formatter:on
		}
	}

	@Configuration
	static class JwtDecoderConfig {
		@Bean
		public JwtDecoder jwtDecoder() {
			return mock(JwtDecoder.class);
		}
	}

	@RestController
	static class BasicController {
		@GetMapping("/")
		public String get() {
			return "ok";
		}

		@PostMapping("/post")
		public String post() {
			return "post";
		}

		@RequestMapping(value = "/authenticated", method = { GET, POST })
		public String authenticated(@AuthenticationPrincipal Authentication authentication) {
			return authentication.getName();
		}

		@GetMapping("/requires-read-scope")
		public String requiresReadScope(@AuthenticationPrincipal JwtAuthenticationToken token) {
			return token.getAuthorities().stream()
					.map(GrantedAuthority::getAuthority)
					.filter(auth -> auth.endsWith("message:read"))
					.findFirst().orElse(null);
		}

		@GetMapping("/ms-requires-read-scope")
		@PreAuthorize("hasAuthority('SCOPE_message:read')")
		public String msRequiresReadScope(@AuthenticationPrincipal JwtAuthenticationToken token) {
			return requiresReadScope(token);
		}

		@GetMapping("/ms-deny")
		@PreAuthorize("denyAll")
		public String deny() {
			return "hmm, that's odd";
		}
	}

	@Configuration
	static class WebServerConfig implements BeanPostProcessor, EnvironmentAware {
		private final MockWebServer server = new MockWebServer();

		@PreDestroy
		public void shutdown() throws IOException {
			this.server.shutdown();
		}

		@Override
		public void setEnvironment(Environment environment) {
			if (environment instanceof ConfigurableEnvironment) {
				((ConfigurableEnvironment) environment)
						.getPropertySources().addFirst(new MockWebServerPropertySource());
			}
		}

		@Bean
		public MockWebServer web() {
			return this.server;
		}

		private class MockWebServerPropertySource extends PropertySource {

			public MockWebServerPropertySource() {
				super("mockwebserver");
			}

			@Override
			public Object getProperty(String name) {
				if ("mockwebserver.url".equals(name)) {
					return WebServerConfig.this.server.url("/.well-known/jwks.json").toString();
				} else {
					return null;
				}
			}
		}
	}

	@Configuration
	static class RestOperationsConfig {
		RestOperations rest = mock(RestOperations.class);

		@Bean
		RestOperations rest() {
			return this.rest;
		}

		@Bean
		NimbusJwtDecoder jwtDecoder() {
			return withJwkSetUri("https://example.org/.well-known/jwks.json")
					.restOperations(this.rest).build();
		}

		@Bean
		NimbusOpaqueTokenIntrospector tokenIntrospectionClient() {
			return new NimbusOpaqueTokenIntrospector("https://example.org/introspect", this.rest);
		}
	}

	private static <T> void registerMockBean(GenericApplicationContext context, String name, Class<T> clazz) {
		context.registerBean(name, clazz, () -> mock(clazz));
	}

	private static class BearerTokenRequestPostProcessor implements RequestPostProcessor {
		private boolean asRequestParameter;

		private String token;

		public BearerTokenRequestPostProcessor(String token) {
			this.token = token;
		}

		public BearerTokenRequestPostProcessor asParam() {
			this.asRequestParameter = true;
			return this;
		}

		@Override
		public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
			if (this.asRequestParameter) {
				request.setParameter("access_token", this.token);
			} else {
				request.addHeader("Authorization", "Bearer " + this.token);
			}

			return request;
		}
	}

	private static BearerTokenRequestPostProcessor bearerToken(String token) {
		return new BearerTokenRequestPostProcessor(token);
	}

	private static ResultMatcher invalidRequestHeader(String message) {
		return header().string(HttpHeaders.WWW_AUTHENTICATE,
				AllOf.allOf(
						new StringStartsWith("Bearer " +
								"error=\"invalid_request\", " +
								"error_description=\""),
						new StringContains(message),
						new StringEndsWith(", " +
								"error_uri=\"https://tools.ietf.org/html/rfc6750#section-3.1\"")
						)
				);
	}

	private static ResultMatcher invalidTokenHeader(String message) {
		return header().string(HttpHeaders.WWW_AUTHENTICATE,
				AllOf.allOf(
						new StringStartsWith("Bearer " +
								"error=\"invalid_token\", " +
								"error_description=\""),
						new StringContains(message),
						new StringEndsWith(", " +
								"error_uri=\"https://tools.ietf.org/html/rfc6750#section-3.1\"")
				)
		);
	}

	private static ResultMatcher insufficientScopeHeader() {
		return header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer " +
				"error=\"insufficient_scope\"" +
				", error_description=\"The request requires higher privileges than provided by the access token.\"" +
				", error_uri=\"https://tools.ietf.org/html/rfc6750#section-3.1\"");
	}

	private void mockWebServer(String response) {
		this.web.enqueue(new MockResponse()
				.setResponseCode(200)
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				.setBody(response));
	}

	private void mockRestOperations(String response) {
		RestOperations rest = this.spring.getContext().getBean(RestOperations.class);
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_JSON);
		ResponseEntity<String> entity = new ResponseEntity<>(response, headers, HttpStatus.OK);
		when(rest.exchange(any(RequestEntity.class), eq(String.class)))
				.thenReturn(entity);
	}

	private <T> T bean(Class<T> beanClass) {
		return this.spring.getContext().getBean(beanClass);
	}

	private <T> T verifyBean(Class<T> beanClass) {
		return verify(this.spring.getContext().getBean(beanClass));
	}

	private String json(String name) throws IOException {
		return resource(name + ".json");
	}

	private String jwks(String name) throws IOException {
		return resource(name + ".jwks");
	}

	private String token(String name) throws IOException {
		return resource(name + ".token");
	}

	private String resource(String suffix) throws IOException {
		String name = this.getClass().getSimpleName() + "-" + suffix;
		ClassPathResource resource = new ClassPathResource(name, this.getClass());
		try ( BufferedReader reader = new BufferedReader(new FileReader(resource.getFile())) ) {
			return reader.lines().collect(Collectors.joining());
		}
	}
}
