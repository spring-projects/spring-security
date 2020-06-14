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
package org.springframework.security.config.http;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletRequest;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import net.minidev.json.JSONObject;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.hamcrest.core.AllOf;
import org.hamcrest.core.StringContains;
import org.hamcrest.core.StringEndsWith;
import org.hamcrest.core.StringStartsWith;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.w3c.dom.Element;

import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanReference;
import org.springframework.beans.factory.parsing.BeanDefinitionParsingException;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParserDelegate;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.beans.factory.xml.XmlReaderContext;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.TestKeys;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestOperations;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.core.StringStartsWith.startsWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.security.config.http.JwtBeanDefinitionParser.DECODER_REF;
import static org.springframework.security.config.http.JwtBeanDefinitionParser.JWK_SET_URI;
import static org.springframework.security.config.http.OAuth2ResourceServerBeanDefinitionParser.AUTHENTICATION_MANAGER_RESOLVER_REF;
import static org.springframework.security.config.http.OpaqueTokenBeanDefinitionParser.INTROSPECTION_URI;
import static org.springframework.security.config.http.OpaqueTokenBeanDefinitionParser.INTROSPECTOR_REF;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.ISS;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.SUB;
import static org.springframework.security.oauth2.jwt.TestJwts.jwt;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 *
 * @author Josh Cummings
 */
@RunWith(SpringJUnit4ClassRunner.class)
@SecurityTestExecutionListeners
public class OAuth2ResourceServerBeanDefinitionParserTests {
	private static final String CONFIG_LOCATION_PREFIX =
			"classpath:org/springframework/security/config/http/OAuth2ResourceServerBeanDefinitionParserTests";

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Autowired(required = false)
	MockWebServer web;

	@Test
	public void getWhenValidBearerTokenThenAcceptsRequest() throws Exception {
		this.spring.configLocations(xml("JwtRestOperations"), xml("Jwt")).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("ValidNoScopes");

		this.mvc.perform(get("/")
				.header("Authorization", "Bearer " + token))
				.andExpect(status().isNotFound());
	}

	@Test
	public void getWhenUsingJwkSetUriThenAcceptsRequest() throws Exception {
		this.spring.configLocations(xml("WebServer"), xml("JwkSetUri")).autowire();
		mockWebServer(jwks("Default"));
		String token = this.token("ValidNoScopes");

		this.mvc.perform(get("/")
				.header("Authorization", "Bearer " + token))
				.andExpect(status().isNotFound());
	}

	@Test
	public void jwkSetUriWithRestOperations() throws Exception {
		spring.configLocations(xml("WebServer"), xml("JwkSetUriRestOperations")).autowire();

		RestOperations restOperations = spring.getContext().getBean(RestOperations.class);
		when(restOperations.exchange(any(), eq(String.class))).thenThrow(new IllegalStateException("custom rest-operations"));

		assertThatThrownBy(() -> {
			mvc.perform(get("/")
					.header("Authorization", "Bearer " + token("ValidNoScopes")));
		}).hasRootCauseInstanceOf(IllegalStateException.class)
				.hasRootCauseMessage("custom rest-operations");

		verify(restOperations).exchange(any(), eq(String.class));
		verifyNoMoreInteractions(restOperations);
	}

	@Test
	public void getWhenExpiredBearerTokenThenInvalidToken()
			throws Exception {

		this.spring.configLocations(xml("JwtRestOperations"), xml("Jwt")).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("Expired");

		this.mvc.perform(get("/")
				.header("Authorization", "Bearer " + token))
				.andExpect(status().isUnauthorized())
				.andExpect(invalidTokenHeader("An error occurred while attempting to decode the Jwt"));
	}

	@Test
	public void getWhenBadJwkEndpointThenInvalidToken()
			throws Exception {

		this.spring.configLocations(xml("JwtRestOperations"), xml("Jwt")).autowire();
		mockRestOperations("malformed");
		String token = this.token("ValidNoScopes");

		this.mvc.perform(get("/")
				.header("Authorization", "Bearer " + token))
				.andExpect(status().isUnauthorized())
				.andExpect(header().string("WWW-Authenticate", "Bearer"));
	}

	@Test
	public void getWhenUnavailableJwkEndpointThenInvalidToken()
			throws Exception {

		this.spring.configLocations(xml("WebServer"), xml("JwkSetUri")).autowire();
		this.web.shutdown();
		String token = this.token("ValidNoScopes");

		this.mvc.perform(get("/")
				.header("Authorization", "Bearer " + token))
				.andExpect(status().isUnauthorized())
				.andExpect(header().string("WWW-Authenticate", "Bearer"));
	}

	@Test
	public void getWhenMalformedBearerTokenThenInvalidToken()
			throws Exception {

		this.spring.configLocations(xml("JwkSetUri")).autowire();

		this.mvc.perform(get("/")
				.header("Authorization", "Bearer an\"invalid\"token"))
				.andExpect(status().isUnauthorized())
				.andExpect(invalidTokenHeader("Bearer token is malformed"));
	}

	@Test
	public void getWhenMalformedPayloadThenInvalidToken()
			throws Exception {

		this.spring.configLocations(xml("JwtRestOperations"), xml("Jwt")).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("MalformedPayload");

		this.mvc.perform(get("/").header("Authorization", "Bearer " + token))
				.andExpect(status().isUnauthorized())
				.andExpect(invalidTokenHeader("An error occurred while attempting to decode the Jwt: Malformed payload"));
	}

	@Test
	public void getWhenUnsignedBearerTokenThenInvalidToken()
			throws Exception {

		this.spring.configLocations(xml("JwkSetUri")).autowire();
		String token = this.token("Unsigned");

		this.mvc.perform(get("/").header("Authorization", "Bearer " + token))
				.andExpect(status().isUnauthorized())
				.andExpect(invalidTokenHeader("Unsupported algorithm of none"));
	}

	@Test
	public void getWhenBearerTokenBeforeNotBeforeThenInvalidToken()
			throws Exception {

		this.spring.configLocations(xml("JwtRestOperations"), xml("Jwt")).autowire();
		this.mockRestOperations(jwks("Default"));
		String token = this.token("TooEarly");

		this.mvc.perform(get("/").header("Authorization", "Bearer " + token))
				.andExpect(status().isUnauthorized())
				.andExpect(invalidTokenHeader("An error occurred while attempting to decode the Jwt"));
	}

	@Test
	public void getWhenBearerTokenInTwoPlacesThenInvalidRequest()
			throws Exception {

		this.spring.configLocations(xml("JwkSetUri")).autowire();

		this.mvc.perform(get("/")
				.header("Authorization", "Bearer token")
				.param("access_token", "token"))
				.andExpect(status().isBadRequest())
				.andExpect(invalidRequestHeader("Found multiple bearer tokens in the request"));
	}

	@Test
	public void getWhenBearerTokenInTwoParametersThenInvalidRequest()
			throws Exception {

		this.spring.configLocations(xml("JwkSetUri")).autowire();

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("access_token", "token1");
		params.add("access_token", "token2");

		this.mvc.perform(get("/")
				.params(params))
				.andExpect(status().isBadRequest())
				.andExpect(invalidRequestHeader("Found multiple bearer tokens in the request"));
	}

	@Test
	public void postWhenBearerTokenAsFormParameterThenIgnoresToken()
			throws Exception {

		this.spring.configLocations(xml("JwkSetUri")).autowire();

		this.mvc.perform(post("/") // engage csrf
				.param("access_token", "token"))
				.andExpect(status().isForbidden())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer")); // different from DSL
	}

	@Test
	public void getWhenNoBearerTokenThenUnauthorized()
			throws Exception {

		this.spring.configLocations(xml("JwkSetUri")).autowire();

		this.mvc.perform(get("/"))
				.andExpect(status().isUnauthorized())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer"));
	}

	@Test
	public void getWhenSufficientlyScopedBearerTokenThenAcceptsRequest()
			throws Exception {

		this.spring.configLocations(xml("JwtRestOperations"), xml("Jwt")).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("ValidMessageReadScope");

		this.mvc.perform(get("/requires-read-scope")
				.header("Authorization", "Bearer " + token))
				.andExpect(status().isNotFound());
	}

	@Test
	public void getWhenInsufficientScopeThenInsufficientScopeError()
			throws Exception {

		this.spring.configLocations(xml("JwtRestOperations"), xml("Jwt")).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("ValidNoScopes");

		this.mvc.perform(get("/requires-read-scope")
				.header("Authorization", "Bearer " + token))
				.andExpect(status().isForbidden())
				.andExpect(insufficientScopeHeader());
	}

	@Test
	public void getWhenInsufficientScpThenInsufficientScopeError()
			throws Exception {

		this.spring.configLocations(xml("JwtRestOperations"), xml("Jwt")).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("ValidMessageWriteScp");

		this.mvc.perform(get("/requires-read-scope")
				.header("Authorization", "Bearer " + token))
				.andExpect(status().isForbidden())
				.andExpect(insufficientScopeHeader());
	}

	@Test
	public void getWhenAuthorizationServerHasNoMatchingKeyThenInvalidToken()
			throws Exception {

		this.spring.configLocations(xml("JwtRestOperations"), xml("Jwt")).autowire();
		mockRestOperations(jwks("Empty"));
		String token = this.token("ValidNoScopes");

		this.mvc.perform(get("/")
				.header("Authorization", "Bearer " + token))
				.andExpect(status().isUnauthorized())
				.andExpect(invalidTokenHeader("An error occurred while attempting to decode the Jwt"));
	}

	@Test
	public void getWhenAuthorizationServerHasMultipleMatchingKeysThenOk()
			throws Exception {

		this.spring.configLocations(xml("JwtRestOperations"), xml("Jwt")).autowire();
		mockRestOperations(jwks("TwoKeys"));
		String token = this.token("ValidNoScopes");

		this.mvc.perform(get("/authenticated")
				.header("Authorization", "Bearer " + token))
				.andExpect(status().isNotFound());
	}

	@Test
	public void getWhenKeyMatchesByKidThenOk()
			throws Exception {

		this.spring.configLocations(xml("JwtRestOperations"), xml("Jwt")).autowire();
		mockRestOperations(jwks("TwoKeys"));
		String token = this.token("Kid");

		this.mvc.perform(get("/authenticated")
				.header("Authorization", "Bearer " + token))
				.andExpect(status().isNotFound());
	}

	// -- Resource Server should not engage csrf

	@Test
	public void postWhenValidBearerTokenAndNoCsrfTokenThenOk()
			throws Exception {

		this.spring.configLocations(xml("JwtRestOperations"), xml("Jwt")).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("ValidNoScopes");

		this.mvc.perform(post("/authenticated")
				.header("Authorization", "Bearer " + token))
				.andExpect(status().isNotFound());
	}

	@Test
	public void postWhenNoBearerTokenThenCsrfDenies()
			throws Exception {

		this.spring.configLocations(xml("JwkSetUri")).autowire();

		this.mvc.perform(post("/authenticated"))
				.andExpect(status().isForbidden())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer")); // different from DSL
	}

	@Test
	public void postWhenExpiredBearerTokenAndNoCsrfThenInvalidToken()
			throws Exception {

		this.spring.configLocations(xml("JwtRestOperations"), xml("Jwt")).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("Expired");

		this.mvc.perform(post("/authenticated")
				.header("Authorization", "Bearer " + token))
				.andExpect(status().isUnauthorized())
				.andExpect(invalidTokenHeader("An error occurred while attempting to decode the Jwt"));
	}

	// -- Resource Server should not create sessions

	@Test
	public void requestWhenJwtThenSessionIsNotCreated()
			throws Exception {

		this.spring.configLocations(xml("JwtRestOperations"), xml("Jwt")).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("ValidNoScopes");

		MvcResult result = this.mvc.perform(get("/")
				.header("Authorization", "Bearer " + token))
				.andExpect(status().isNotFound())
				.andReturn();

		assertThat(result.getRequest().getSession(false)).isNull();
	}

	@Test
	public void requestWhenIntrospectionThenSessionIsNotCreated()
			throws Exception {

		this.spring.configLocations(xml("WebServer"), xml("IntrospectionUri")).autowire();
		mockWebServer(json("Active"));

		MvcResult result = this.mvc.perform(get("/authenticated")
				.header("Authorization", "Bearer token"))
				.andExpect(status().isNotFound())
				.andReturn();

		assertThat(result.getRequest().getSession(false)).isNull();
	}

	@Test
	public void requestWhenNoBearerTokenThenSessionIsCreated()
			throws Exception {

		this.spring.configLocations(xml("JwkSetUri")).autowire();

		MvcResult result = this.mvc.perform(get("/"))
				.andExpect(status().isUnauthorized())
				.andReturn();

		assertThat(result.getRequest().getSession(false)).isNotNull();
	}

	@Test
	public void requestWhenSessionManagementConfiguredThenUses()
			throws Exception {

		this.spring.configLocations(xml("JwtRestOperations"), xml("AlwaysSessionCreation")).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("ValidNoScopes");

		MvcResult result = this.mvc.perform(get("/")
				.header("Authorization", "Bearer " + token))
				.andExpect(status().isNotFound())
				.andReturn();

		assertThat(result.getRequest().getSession(false)).isNotNull();
	}

	// -- custom bearer token resolver

	@Test
	public void getWhenCustomBearerTokenResolverThenUses() throws Exception {
		this.spring.configLocations(xml("MockBearerTokenResolver"), xml("MockJwtDecoder"),
				xml("BearerTokenResolver")).autowire();

		JwtDecoder decoder = this.spring.getContext().getBean(JwtDecoder.class);
		when(decoder.decode("token")).thenReturn(jwt().build());

		BearerTokenResolver bearerTokenResolver = this.spring.getContext().getBean(BearerTokenResolver.class);
		when(bearerTokenResolver.resolve(any(HttpServletRequest.class)))
				.thenReturn("token");

		this.mvc.perform(get("/"))
				.andExpect(status().isNotFound());

		verify(decoder).decode("token");
		verify(bearerTokenResolver).resolve(any(HttpServletRequest.class));
	}

	@Test
	public void requestWhenBearerTokenResolverAllowsRequestBodyThenEitherHeaderOrRequestBodyIsAccepted()
			throws Exception {

		this.spring.configLocations(xml("MockJwtDecoder"), xml("AllowBearerTokenInBody")).autowire();

		JwtDecoder decoder = this.spring.getContext().getBean(JwtDecoder.class);
		when(decoder.decode(anyString())).thenReturn(jwt().build());

		this.mvc.perform(get("/authenticated")
				.header("Authorization", "Bearer token"))
				.andExpect(status().isNotFound());

		this.mvc.perform(post("/authenticated")
				.param("access_token", "token"))
				.andExpect(status().isNotFound());
	}

	@Test
	public void requestWhenBearerTokenResolverAllowsQueryParameterThenEitherHeaderOrQueryParameterIsAccepted()
			throws Exception {

		this.spring.configLocations(xml("MockJwtDecoder"), xml("AllowBearerTokenInQuery")).autowire();

		JwtDecoder decoder = this.spring.getContext().getBean(JwtDecoder.class);
		when(decoder.decode(anyString())).thenReturn(jwt().build());

		this.mvc.perform(get("/authenticated")
				.header("Authorization", "Bearer token"))
				.andExpect(status().isNotFound());

		this.mvc.perform(get("/authenticated")
				.param("access_token", "token"))
				.andExpect(status().isNotFound());

		verify(decoder, times(2)).decode("token");
	}

	@Test
	public void requestWhenBearerTokenResolverAllowsRequestBodyAndRequestContainsTwoTokensThenInvalidRequest()
			throws Exception {

		this.spring.configLocations(xml("MockJwtDecoder"), xml("AllowBearerTokenInBody")).autowire();

		this.mvc.perform(post("/authenticated")
				.param("access_token", "token")
				.header("Authorization", "Bearer token")
				.with(csrf()))
				.andExpect(status().isBadRequest())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("invalid_request")));
	}

	@Test
	public void requestWhenBearerTokenResolverAllowsQueryParameterAndRequestContainsTwoTokensThenInvalidRequest()
			throws Exception {

		this.spring.configLocations(xml("MockJwtDecoder"), xml("AllowBearerTokenInQuery")).autowire();

		this.mvc.perform(get("/authenticated")
				.header("Authorization", "Bearer token")
				.param("access_token", "token"))
				.andExpect(status().isBadRequest())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("invalid_request")));
	}

	@Test
	public void getBearerTokenResolverWhenNoResolverSpecifiedThenTheDefaultIsUsed() {
		OAuth2ResourceServerBeanDefinitionParser oauth2 =
				new OAuth2ResourceServerBeanDefinitionParser
						(mock(BeanReference.class), mock(List.class), mock(Map.class),
								mock(Map.class), mock(List.class));

		assertThat(oauth2.getBearerTokenResolver(mock(Element.class)))
				.isInstanceOf(RootBeanDefinition.class);
	}

	// -- custom jwt decoder

	@Test
	public void requestWhenCustomJwtDecoderThenUsed()
			throws Exception {

		this.spring.configLocations(xml("MockJwtDecoder"), xml("Jwt")).autowire();

		JwtDecoder decoder = this.spring.getContext().getBean(JwtDecoder.class);

		when(decoder.decode(anyString())).thenReturn(jwt().build());

		this.mvc.perform(get("/authenticated")
				.header("Authorization", "Bearer token"))
				.andExpect(status().isNotFound());

		verify(decoder).decode("token");
	}

	@Test
	public void configureWhenDecoderAndJwkSetUriThenException() {
		assertThatThrownBy(() -> this.spring.configLocations(xml("JwtDecoderAndJwkSetUri")).autowire())
				.isInstanceOf(BeanDefinitionParsingException.class);
	}

	// -- exception handling

	@Test
	public void requestWhenRealmNameConfiguredThenUsesOnUnauthenticated()
			throws Exception {

		this.spring.configLocations(xml("MockJwtDecoder"), xml("AuthenticationEntryPoint")).autowire();

		JwtDecoder decoder = this.spring.getContext().getBean(JwtDecoder.class);
		when(decoder.decode(anyString())).thenThrow(JwtException.class);

		this.mvc.perform(get("/authenticated")
				.header("Authorization", "Bearer invalid_token"))
				.andExpect(status().isUnauthorized())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, startsWith("Bearer realm=\"myRealm\"")));
	}

	@Test
	public void requestWhenRealmNameConfiguredThenUsesOnAccessDenied()
			throws Exception {

		this.spring.configLocations(xml("MockJwtDecoder"), xml("AccessDeniedHandler")).autowire();

		JwtDecoder decoder = this.spring.getContext().getBean(JwtDecoder.class);
		when(decoder.decode(anyString())).thenReturn(jwt().build());

		this.mvc.perform(get("/authenticated")
				.header("Authorization", "Bearer insufficiently_scoped"))
				.andExpect(status().isForbidden())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, startsWith("Bearer realm=\"myRealm\"")));
	}

	// -- token validator

	@Test
	public void requestWhenCustomJwtValidatorFailsThenCorrespondingErrorMessage()
			throws Exception {

		this.spring.configLocations(xml("MockJwtValidator"), xml("Jwt")).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("ValidNoScopes");

		OAuth2TokenValidator<Jwt> jwtValidator =
				this.spring.getContext().getBean(OAuth2TokenValidator.class);

		OAuth2Error error = new OAuth2Error("custom-error", "custom-description", "custom-uri");

		when(jwtValidator.validate(any(Jwt.class))).thenReturn(OAuth2TokenValidatorResult.failure(error));

		this.mvc.perform(get("/")
				.header("Authorization", "Bearer " + token))
				.andExpect(status().isUnauthorized())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("custom-description")));
	}

	@Test
	public void requestWhenClockSkewSetThenTimestampWindowRelaxedAccordingly()
			throws Exception {

		this.spring.configLocations(xml("UnexpiredJwtClockSkew"), xml("Jwt")).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("ExpiresAt4687177990");

		this.mvc.perform(get("/")
				.header("Authorization", "Bearer " + token))
				.andExpect(status().isNotFound());
	}

	@Test
	public void requestWhenClockSkewSetButJwtStillTooLateThenReportsExpired()
			throws Exception {

		this.spring.configLocations(xml("ExpiredJwtClockSkew"), xml("Jwt")).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("ExpiresAt4687177990");

		this.mvc.perform(get("/")
				.header("Authorization", "Bearer " + token))
				.andExpect(status().isUnauthorized())
				.andExpect(invalidTokenHeader("Jwt expired at"));
	}

	// -- converter

	@Test
	public void requestWhenJwtAuthenticationConverterThenUsed()
			throws Exception {

		this.spring.configLocations(xml("MockJwtDecoder"), xml("MockJwtAuthenticationConverter"), xml("JwtAuthenticationConverter")).autowire();

		Converter<Jwt, JwtAuthenticationToken> jwtAuthenticationConverter =
				(Converter<Jwt, JwtAuthenticationToken>) this.spring.getContext().getBean("jwtAuthenticationConverter");
		when(jwtAuthenticationConverter.convert(any(Jwt.class)))
				.thenReturn(new JwtAuthenticationToken(jwt().build(), Collections.emptyList()));

		JwtDecoder jwtDecoder = this.spring.getContext().getBean(JwtDecoder.class);
		when(jwtDecoder.decode(anyString())).thenReturn(jwt().build());

		this.mvc.perform(get("/")
				.header("Authorization", "Bearer token"))
				.andExpect(status().isNotFound());

		verify(jwtAuthenticationConverter).convert(any(Jwt.class));
	}

	// -- single key

	@Test
	public void requestWhenUsingPublicKeyAndValidTokenThenAuthenticates()
			throws Exception {

		this.spring.configLocations(xml("SingleKey"), xml("Jwt")).autowire();
		String token = this.token("ValidNoScopes");

		this.mvc.perform(get("/")
				.header("Authorization", "Bearer " + token))
				.andExpect(status().isNotFound());
	}

	@Test
	public void requestWhenUsingPublicKeyAndSignatureFailsThenReturnsInvalidToken()
			throws Exception {

		this.spring.configLocations(xml("SingleKey"), xml("Jwt")).autowire();
		String token = this.token("WrongSignature");

		this.mvc.perform(get("/")
				.header("Authorization", "Bearer " + token))
				.andExpect(invalidTokenHeader("signature"));
	}

	@Test
	public void requestWhenUsingPublicKeyAlgorithmDoesNotMatchThenReturnsInvalidToken()
			throws Exception {

		this.spring.configLocations(xml("SingleKey"), xml("Jwt")).autowire();
		String token = this.token("WrongAlgorithm");

		this.mvc.perform(get("/")
				.header("Authorization", "Bearer " + token))
				.andExpect(invalidTokenHeader("algorithm"));
	}

	// -- opaque

	@Test
	public void getWhenIntrospectingThenOk() throws Exception {
		this.spring.configLocations(xml("OpaqueTokenRestOperations"), xml("OpaqueToken")).autowire();
		mockRestOperations(json("Active"));

		this.mvc.perform(get("/authenticated")
				.header("Authorization", "Bearer token"))
				.andExpect(status().isNotFound());
	}

	@Test
	public void getWhenIntrospectionFailsThenUnauthorized() throws Exception {
		this.spring.configLocations(xml("OpaqueTokenRestOperations"), xml("OpaqueToken")).autowire();
		mockRestOperations(json("Inactive"));

		this.mvc.perform(get("/")
				.header("Authorization", "Bearer token"))
				.andExpect(status().isUnauthorized())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE,
						containsString("Provided token isn't active")));
	}

	@Test
	public void getWhenIntrospectionLacksScopeThenForbidden() throws Exception {
		this.spring.configLocations(xml("OpaqueTokenRestOperations"), xml("OpaqueToken")).autowire();
		mockRestOperations(json("ActiveNoScopes"));

		this.mvc.perform(get("/requires-read-scope")
				.header("Authorization", "Bearer token"))
				.andExpect(status().isForbidden())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("scope")));
	}

	@Test
	public void configureWhenOnlyIntrospectionUrlThenException() {
		assertThatCode(() -> this.spring.configLocations(xml("OpaqueTokenHalfConfigured")).autowire())
				.isInstanceOf(BeanDefinitionParsingException.class);
	}

	@Test
	public void configureWhenIntrospectorAndIntrospectionUriThenError() {
		assertThatCode(() -> this.spring.configLocations(xml("OpaqueTokenAndIntrospectionUri")).autowire())
				.isInstanceOf(BeanDefinitionParsingException.class);
	}

	// -- authentication manager resolver

	@Test
	public void getWhenAuthenticationManagerResolverThenUses() throws Exception {
		this.spring.configLocations(xml("AuthenticationManagerResolver")).autowire();

		AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver =
				this.spring.getContext().getBean(AuthenticationManagerResolver.class);
		when(authenticationManagerResolver.resolve(any(HttpServletRequest.class)))
				.thenReturn(authentication -> new JwtAuthenticationToken(jwt().build(), Collections.emptyList()));

		this.mvc.perform(get("/")
				.header("Authorization", "Bearer token"))
				.andExpect(status().isNotFound());

		verify(authenticationManagerResolver).resolve(any(HttpServletRequest.class));
	}

	@Test
	public void getWhenMultipleIssuersThenUsesIssuerClaimToDifferentiate() throws Exception {
		this.spring.configLocations(xml("WebServer"), xml("MultipleIssuers")).autowire();

		MockWebServer server = this.spring.getContext().getBean(MockWebServer.class);
		String metadata = "{\n"
				+ "    \"issuer\": \"%s\", \n"
				+ "    \"jwks_uri\": \"%s/.well-known/jwks.json\" \n"
				+ "}";
		String jwkSet = jwkSet();
		String issuerOne = server.url("/issuerOne").toString();
		String issuerTwo = server.url("/issuerTwo").toString();
		String issuerThree = server.url("/issuerThree").toString();
		String jwtOne = jwtFromIssuer(issuerOne);
		String jwtTwo = jwtFromIssuer(issuerTwo);
		String jwtThree = jwtFromIssuer(issuerThree);

		mockWebServer(String.format(metadata, issuerOne, issuerOne));
		mockWebServer(jwkSet);

		this.mvc.perform(get("/authenticated")
				.header("Authorization", "Bearer " + jwtOne))
				.andExpect(status().isNotFound());

		mockWebServer(String.format(metadata, issuerTwo, issuerTwo));
		mockWebServer(jwkSet);

		this.mvc.perform(get("/authenticated")
				.header("Authorization", "Bearer " + jwtTwo))
				.andExpect(status().isNotFound());

		mockWebServer(String.format(metadata, issuerThree, issuerThree));
		mockWebServer(jwkSet);

		this.mvc.perform(get("/authenticated")
				.header("Authorization", "Bearer " + jwtThree))
				.andExpect(status().isUnauthorized())
				.andExpect(invalidTokenHeader("Invalid issuer"));
	}

	// -- In combination with other authentication providers

	@Test
	public void requestWhenBasicAndResourceServerEntryPointsThenBearerTokenPresides()
			throws Exception { // different from DSL

		this.spring.configLocations(xml("MockJwtDecoder"), xml("BasicAndResourceServer")).autowire();

		JwtDecoder decoder = this.spring.getContext().getBean(JwtDecoder.class);
		when(decoder.decode(anyString())).thenThrow(JwtException.class);

		this.mvc.perform(get("/authenticated")
				.with(httpBasic("some", "user")))
				.andExpect(status().isUnauthorized())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, startsWith("Basic")));

		this.mvc.perform(get("/authenticated"))
				.andExpect(status().isUnauthorized())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, startsWith("Bearer")));

		this.mvc.perform(get("/authenticated")
				.header("Authorization", "Bearer invalid_token"))
				.andExpect(status().isUnauthorized())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, startsWith("Bearer")));
	}

	@Test
	public void requestWhenFormLoginAndResourceServerEntryPointsThenSessionCreatedByRequest()
			throws Exception { // different from DSL

		this.spring.configLocations(xml("MockJwtDecoder"), xml("FormAndResourceServer")).autowire();

		JwtDecoder decoder = this.spring.getContext().getBean(JwtDecoder.class);
		when(decoder.decode(anyString())).thenThrow(JwtException.class);

		MvcResult result =
				this.mvc.perform(get("/authenticated"))
						.andExpect(status().isUnauthorized())
						.andReturn();

		assertThat(result.getRequest().getSession(false)).isNotNull();

		result =
				this.mvc.perform(get("/authenticated")
						.header("Authorization", "Bearer token"))
						.andExpect(status().isUnauthorized())
						.andReturn();

		assertThat(result.getRequest().getSession(false)).isNull();
	}

	@Test
	public void getWhenAlsoUsingHttpBasicThenCorrectProviderEngages()
			throws Exception {

		this.spring.configLocations(xml("JwtRestOperations"), xml("BasicAndResourceServer")).autowire();
		mockRestOperations(jwks("Default"));
		String token = this.token("ValidNoScopes");

		this.mvc.perform(get("/authenticated")
				.header("Authorization", "Bearer " + token))
				.andExpect(status().isNotFound());

		this.mvc.perform(get("/authenticated")
				.with(httpBasic("user", "password")))
				.andExpect(status().isNotFound());
	}

	// -- Incorrect Configuration

	@Test
	public void configuredWhenMissingJwtAuthenticationProviderThenWiringException() {
		assertThatCode(() -> this.spring.configLocations(xml("Jwtless")).autowire())
				.isInstanceOf(BeanDefinitionParsingException.class)
				.hasMessageContaining("Please select one");
	}

	@Test
	public void configureWhenMissingJwkSetUriThenWiringException() {
		assertThatCode(() -> this.spring.configLocations(xml("JwtHalfConfigured")).autowire())
				.isInstanceOf(BeanDefinitionParsingException.class)
				.hasMessageContaining("Please specify either");
	}

	@Test
	public void configureWhenUsingBothAuthenticationManagerResolverAndJwtThenException() {
		assertThatCode(() -> this.spring.configLocations(xml("AuthenticationManagerResolverPlusOtherConfig")).autowire())
				.isInstanceOf(BeanDefinitionParsingException.class)
				.hasMessageContaining("authentication-manager-resolver-ref");
	}

	@Test
	public void validateConfigurationWhenMoreThanOneResourceServerModeThenError() {
		OAuth2ResourceServerBeanDefinitionParser parser = new OAuth2ResourceServerBeanDefinitionParser
				(null, null, null, null, null);
		Element element = mock(Element.class);
		when(element.hasAttribute(AUTHENTICATION_MANAGER_RESOLVER_REF)).thenReturn(true);
		Element child = mock(Element.class);
		ParserContext pc = new ParserContext(mock(XmlReaderContext.class), mock(BeanDefinitionParserDelegate.class));

		parser.validateConfiguration(element, child, null, pc);
		verify(pc.getReaderContext()).error(anyString(), eq(element));
		reset(pc.getReaderContext());

		parser.validateConfiguration(element, null, child, pc);
		verify(pc.getReaderContext()).error(anyString(), eq(element));
	}

	@Test
	public void validateConfigurationWhenNoResourceServerModeThenError() {
		OAuth2ResourceServerBeanDefinitionParser parser = new OAuth2ResourceServerBeanDefinitionParser
				(null, null, null, null, null);
		Element element = mock(Element.class);
		when(element.hasAttribute(AUTHENTICATION_MANAGER_RESOLVER_REF)).thenReturn(false);
		ParserContext pc = new ParserContext(mock(XmlReaderContext.class), mock(BeanDefinitionParserDelegate.class));
		parser.validateConfiguration(element, null, null, pc);
		verify(pc.getReaderContext()).error(anyString(), eq(element));
	}

	@Test
	public void validateConfigurationWhenBothJwtAttributesThenError() {
		JwtBeanDefinitionParser parser = new JwtBeanDefinitionParser();
		Element element = mock(Element.class);
		when(element.hasAttribute(JWK_SET_URI)).thenReturn(true);
		when(element.hasAttribute(DECODER_REF)).thenReturn(true);
		ParserContext pc = new ParserContext(mock(XmlReaderContext.class), mock(BeanDefinitionParserDelegate.class));
		parser.validateConfiguration(element, pc);
		verify(pc.getReaderContext()).error(anyString(), eq(element));
	}

	@Test
	public void validateConfigurationWhenNoJwtAttributesThenError() {
		JwtBeanDefinitionParser parser = new JwtBeanDefinitionParser();
		Element element = mock(Element.class);
		when(element.hasAttribute(JWK_SET_URI)).thenReturn(false);
		when(element.hasAttribute(DECODER_REF)).thenReturn(false);
		ParserContext pc = new ParserContext(mock(XmlReaderContext.class), mock(BeanDefinitionParserDelegate.class));
		parser.validateConfiguration(element, pc);
		verify(pc.getReaderContext()).error(anyString(), eq(element));
	}

	@Test
	public void validateConfigurationWhenBothOpaqueTokenModesThenError() {
		OpaqueTokenBeanDefinitionParser parser = new OpaqueTokenBeanDefinitionParser();
		Element element = mock(Element.class);
		when(element.hasAttribute(INTROSPECTION_URI)).thenReturn(true);
		when(element.hasAttribute(INTROSPECTOR_REF)).thenReturn(true);
		ParserContext pc = new ParserContext(mock(XmlReaderContext.class), mock(BeanDefinitionParserDelegate.class));
		parser.validateConfiguration(element, pc);
		verify(pc.getReaderContext()).error(anyString(), eq(element));
	}

	@Test
	public void validateConfigurationWhenNoOpaqueTokenModeThenError() {
		OpaqueTokenBeanDefinitionParser parser = new OpaqueTokenBeanDefinitionParser();
		Element element = mock(Element.class);
		when(element.hasAttribute(INTROSPECTION_URI)).thenReturn(false);
		when(element.hasAttribute(INTROSPECTOR_REF)).thenReturn(false);
		ParserContext pc = new ParserContext(mock(XmlReaderContext.class), mock(BeanDefinitionParserDelegate.class));
		parser.validateConfiguration(element, pc);
		verify(pc.getReaderContext()).error(anyString(), eq(element));
	}

	static class JwtDecoderFactoryBean implements FactoryBean<JwtDecoder> {
		private RestOperations rest;
		private RSAPublicKey key;
		private OAuth2TokenValidator<Jwt> jwtValidator;

		@Override
		public JwtDecoder getObject() {
			NimbusJwtDecoder decoder;
			if (this.key != null) {
				decoder = NimbusJwtDecoder.withPublicKey(this.key).build();
			} else {
				decoder = NimbusJwtDecoder.withJwkSetUri("https://idp.example.org")
						.restOperations(this.rest).build();
			}
			if (this.jwtValidator != null) {
				decoder.setJwtValidator(this.jwtValidator);
			}
			return decoder;
		}

		@Override
		public Class<?> getObjectType() {
			return JwtDecoder.class;
		}

		public void setJwtValidator(OAuth2TokenValidator<Jwt> jwtValidator) {
			this.jwtValidator = jwtValidator;
		}

		public void setKey(RSAPublicKey key) {
			this.key = key;
		}

		public void setRest(RestOperations rest) {
			this.rest = rest;
		}
	}

	static class OpaqueTokenIntrospectorFactoryBean implements FactoryBean<OpaqueTokenIntrospector> {
		private RestOperations rest;

		@Override
		public OpaqueTokenIntrospector getObject() throws Exception {
			return new NimbusOpaqueTokenIntrospector("https://idp.example.org", this.rest);
		}

		@Override
		public Class<?> getObjectType() {
			return OpaqueTokenIntrospector.class;
		}

		public void setRest(RestOperations rest) {
			this.rest = rest;
		}
	}

	static class MockWebServerFactoryBean implements FactoryBean<MockWebServer>, DisposableBean {
		private final MockWebServer web = new MockWebServer();

		@Override
		public void destroy() throws Exception {
			this.web.shutdown();
		}

		@Override
		public MockWebServer getObject() {
			return this.web;
		}

		@Override
		public Class<?> getObjectType() {
			return MockWebServer.class;
		}
	}

	static class MockWebServerPropertiesFactoryBean
			implements FactoryBean<Properties>, DisposableBean {

		MockWebServer web;

		MockWebServerPropertiesFactoryBean(MockWebServer web) {
			this.web = web;
		}

		@Override
		public Properties getObject() {
			Properties p = new Properties();
			p.setProperty("jwk-set-uri", this.web.url("").toString());
			p.setProperty("introspection-uri", this.web.url("").toString());
			p.setProperty("issuer-one", this.web.url("issuerOne").toString());
			p.setProperty("issuer-two", this.web.url("issuerTwo").toString());
			return p;
		}

		@Override
		public Class<?> getObjectType() {
			return Properties.class;
		}

		@Override
		public void destroy() throws Exception {
			this.web.shutdown();
		}
	}

	static class ClockFactoryBean
		implements FactoryBean<Clock> {

		Clock clock;

		@Override
		public Clock getObject() {
			return this.clock;
		}

		@Override
		public Class<?> getObjectType() {
			return Clock.class;
		}

		public void setMillis(long millis) {
			this.clock = Clock.fixed(Instant.ofEpochMilli(millis), ZoneId.systemDefault());
		}
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

	private String jwkSet() {
		return new JWKSet(new RSAKey.Builder(TestKeys.DEFAULT_PUBLIC_KEY)
				.keyID("1").build()).toString();
	}

	private String jwtFromIssuer(String issuer) throws Exception {
		Map<String, Object> claims = new HashMap<>();
		claims.put(ISS, issuer);
		claims.put(SUB, "test-subject");
		claims.put("scope", "message:read");
		JWSObject jws = new JWSObject(
				new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("1").build(),
				new Payload(new JSONObject(claims)));
		jws.sign(new RSASSASigner(TestKeys.DEFAULT_PRIVATE_KEY));
		return jws.serialize();
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

	private <T> T bean(Class<T> beanClass) {
		return this.spring.getContext().getBean(beanClass);
	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}
}
