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

package org.springframework.security.config.web.server;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import jakarta.annotation.PreDestroy;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.apache.http.HttpHeaders;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import reactor.core.publisher.Mono;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.TestJwts;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authorization.HttpStatusServerAccessDeniedHandler;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.support.GenericWebApplicationContext;
import org.springframework.web.reactive.DispatcherHandler;
import org.springframework.web.reactive.config.EnableWebFlux;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for
 * {@link org.springframework.security.config.web.server.ServerHttpSecurity.OAuth2ResourceServerSpec}
 */
@ExtendWith({ SpringTestContextExtension.class })
public class OAuth2ResourceServerSpecTests {

	private String expired = "eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE1MzUwMzc4OTd9.jqZDDjfc2eysX44lHXEIr9XFd2S8vjIZHCccZU-dRWMRJNsQ1QN5VNnJGklqJBXJR4qgla6cmVqPOLkUHDb0sL0nxM5XuzQaG5ZzKP81RV88shFyAiT0fD-6nl1k-Fai-Fu-VkzSpNXgeONoTxDaYhdB-yxmgrgsApgmbOTE_9AcMk-FQDXQ-pL9kynccFGV0lZx4CA7cyknKN7KBxUilfIycvXODwgKCjj_1WddLTCNGYogJJSg__7NoxzqbyWd3udbHVjqYq7GsMMrGB4_2kBD4CkghOSNcRHbT_DIXowxfAVT7PAg7Q0E5ruZsr2zPZacEUDhJ6-wbvlA0FAOUg";

	private String messageReadToken = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJtb2NrLXN1YmplY3QiLCJzY29wZSI6Im1lc3NhZ2U6cmVhZCIsImV4cCI6NDY4ODY0MTQxM30.cRl1bv_dDYcAN5U4NlIVKj8uu4mLMwjABF93P4dShiq-GQ-owzaqTSlB4YarNFgV3PKQvT9wxN1jBpGribvISljakoC0E8wDV-saDi8WxN-qvImYsn1zLzYFiZXCfRIxCmonJpydeiAPRxMTPtwnYDS9Ib0T_iA80TBGd-INhyxUUfrwRW5sqKRbjUciRJhpp7fW2ZYXmi9iPt3HDjRQA4IloJZ7f4-spt5Q9wl5HcQTv1t4XrX4eqhVbE5cCoIkFQnKPOc-jhVM44_eazLU6Xk-CCXP8C_UT5pX0luRS2cJrVFfHp2IR_AWxC-shItg6LNEmNFD4Zc-JLZcr0Q86Q";

	private String messageReadTokenWithKid = "eyJraWQiOiJvbmUiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJtb2NrLXN1YmplY3QiLCJzY29wZSI6Im1lc3NhZ2U6cmVhZCIsImV4cCI6NDY4ODY0MTQ2MX0.Arg3IjlNb_nkEIZpcWAQquvoiaeF_apJzO5ZxSzUQEWixH1Y7yrsW2uco452a7OtAKDNT09IplK8126z_hdI_RRk0CXVsGZYe1qppNIVLEPGv4rHxND4bPv1YA91Q8vG-vDk9rod7EvAuZU1tEP_pWkSkZVAmfuP43bP5FQcO6Q31Aba7Yb7O5qWn9U2MjruPSFvTsIx3hSXgTuJxhNCKeHnTCmv2WdjYWatR7-VujBlHd-ZolysXm7-JPz3kI75omnomG2UqnKkI76sczIpm4ieOp3fSyv-QR-i-3Z_eJ9hS3Ox46Y9NJS6Z-y1g3X0fjVyhLiIJkFV3VA5HrSf_A";

	private String unsignedToken = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJleHAiOi0yMDMzMjI0OTcsImp0aSI6IjEyMyIsInR5cCI6IkpXVCJ9.";

	// @formatter:off
	private String jwkSet = "{\n"
			+ "  \"keys\":[\n"
			+ "    {\n"
			+ "      \"kty\":\"RSA\",\n"
			+ "      \"e\":\"AQAB\",\n"
			+ "      \"use\":\"sig\",\n"
			+ "      \"kid\":\"one\",\n"
			+ "      \"n\":\"0IUjrPZDz-3z0UE4ppcKU36v7hnh8FJjhu3lbJYj0qj9eZiwEJxi9HHUfSK1DhUQG7mJBbYTK1tPYCgre5EkfKh-64VhYUa-vz17zYCmuB8fFj4XHE3MLkWIG-AUn8hNbPzYYmiBTjfGnMKxLHjsbdTiF4mtn-85w366916R6midnAuiPD4HjZaZ1PAsuY60gr8bhMEDtJ8unz81hoQrozpBZJ6r8aR1PrsWb1OqPMloK9kAIutJNvWYKacp8WYAp2WWy72PxQ7Fb0eIA1br3A5dnp-Cln6JROJcZUIRJ-QvS6QONWeS2407uQmS-i-lybsqaH0ldYC7NBEBA5inPQ\"\n"
			+ "    }\n"
			+ "  ]\n"
			+ "}\n";
	// @formatter:on

	private Jwt jwt = TestJwts.jwt().build();

	private String clientId = "client";

	private String clientSecret = "secret";

	// @formatter:off
	private String active = "{\n"
			+ "      \"active\": true,\n"
			+ "      \"client_id\": \"l238j323ds-23ij4\",\n"
			+ "      \"username\": \"jdoe\",\n"
			+ "      \"scope\": \"read write dolphin\",\n"
			+ "      \"sub\": \"Z5O3upPC88QrAjx00dis\",\n"
			+ "      \"aud\": \"https://protected.example.net/resource\",\n"
			+ "      \"iss\": \"https://server.example.com/\",\n"
			+ "      \"exp\": 1419356238,\n"
			+ "      \"iat\": 1419350238,\n"
			+ "      \"extension_field\": \"twenty-seven\"\n"
			+ "     }";
	// @formatter:on

	public final SpringTestContext spring = new SpringTestContext(this);

	WebTestClient client;

	@Autowired
	public void setApplicationContext(ApplicationContext context) {
		this.client = WebTestClient.bindToApplicationContext(context).build();
	}

	@Test
	public void getWhenValidThenReturnsOk() {
		this.spring.register(PublicKeyConfig.class, RootController.class).autowire();
		// @formatter:off
		this.client.get()
				.headers((headers) -> headers
						.setBearerAuth(this.messageReadToken))
				.exchange()
				.expectStatus().isOk();
		// @formatter:on
	}

	@Test
	public void getWhenExpiredThenReturnsInvalidToken() {
		this.spring.register(PublicKeyConfig.class).autowire();
		// @formatter:off
		this.client.get()
				.headers((headers) -> headers
						.setBearerAuth(this.expired))
				.exchange()
				.expectStatus().isUnauthorized()
				.expectHeader().value(HttpHeaders.WWW_AUTHENTICATE, startsWith("Bearer error=\"invalid_token\""));
		// @formatter:on
	}

	@Test
	public void getWhenUnsignedThenReturnsInvalidToken() {
		this.spring.register(PublicKeyConfig.class).autowire();
		// @formatter:off
		this.client.get()
				.headers((headers) -> headers
						.setBearerAuth(this.unsignedToken))
				.exchange()
				.expectStatus().isUnauthorized()
				.expectHeader().value(HttpHeaders.WWW_AUTHENTICATE, startsWith("Bearer error=\"invalid_token\""));
		// @formatter:on
	}

	@Test
	public void getWhenEmptyBearerTokenThenReturnsInvalidToken() {
		this.spring.register(PublicKeyConfig.class).autowire();
		// @formatter:off
		this.client.get()
				.headers((headers) -> headers
						.add("Authorization", "Bearer ")
				)
				.exchange()
				.expectStatus().isUnauthorized()
				.expectHeader().value(HttpHeaders.WWW_AUTHENTICATE, startsWith("Bearer error=\"invalid_token\""));
		// @formatter:on
	}

	@Test
	public void getWhenValidTokenAndPublicKeyInLambdaThenReturnsOk() {
		this.spring.register(PublicKeyInLambdaConfig.class, RootController.class).autowire();
		// @formatter:off
		this.client.get()
				.headers((headers) -> headers
						.setBearerAuth(this.messageReadToken)
				)
				.exchange()
				.expectStatus().isOk();
		// @formatter:on
	}

	@Test
	public void getWhenExpiredTokenAndPublicKeyInLambdaThenReturnsInvalidToken() {
		this.spring.register(PublicKeyInLambdaConfig.class).autowire();
		// @formatter:off
		this.client.get()
				.headers((headers) -> headers
						.setBearerAuth(this.expired)
				)
				.exchange()
				.expectStatus().isUnauthorized()
				.expectHeader().value(HttpHeaders.WWW_AUTHENTICATE, startsWith("Bearer error=\"invalid_token\""));
		// @formatter:on
	}

	@Test
	public void getWhenValidUsingPlaceholderThenReturnsOk() {
		this.spring.register(PlaceholderConfig.class, RootController.class).autowire();
		// @formatter:off
		this.client.get()
				.headers((headers) -> headers
						.setBearerAuth(this.messageReadToken)
				)
				.exchange()
				.expectStatus().isOk();
		// @formatter:on
	}

	@Test
	public void getWhenCustomDecoderThenAuthenticatesAccordingly() {
		this.spring.register(CustomDecoderConfig.class, RootController.class).autowire();
		ReactiveJwtDecoder jwtDecoder = this.spring.getContext().getBean(ReactiveJwtDecoder.class);
		given(jwtDecoder.decode(anyString())).willReturn(Mono.just(this.jwt));
		// @formatter:off
		this.client.get()
				.headers((headers) -> headers
						.setBearerAuth("token")
				)
				.exchange()
				.expectStatus().isOk();
		// @formatter:on
		verify(jwtDecoder).decode(anyString());
	}

	@Test
	public void getWhenUsingJwkSetUriThenConsultsAccordingly() {
		this.spring.register(JwkSetUriConfig.class, RootController.class).autowire();
		MockWebServer mockWebServer = this.spring.getContext().getBean(MockWebServer.class);
		mockWebServer.enqueue(new MockResponse().setBody(this.jwkSet));
		// @formatter:off
		this.client.get()
				.headers((headers) -> headers
						.setBearerAuth(this.messageReadTokenWithKid)
				)
				.exchange()
				.expectStatus().isOk();
		// @formatter:on
	}

	@Test
	public void getWhenUsingJwkSetUriInLambdaThenConsultsAccordingly() {
		this.spring.register(JwkSetUriInLambdaConfig.class, RootController.class).autowire();
		MockWebServer mockWebServer = this.spring.getContext().getBean(MockWebServer.class);
		mockWebServer.enqueue(new MockResponse().setBody(this.jwkSet));
		// @formatter:off
		this.client.get()
				.headers((headers) -> headers
						.setBearerAuth(this.messageReadTokenWithKid)
				)
				.exchange()
				.expectStatus().isOk();
		// @formatter:on
	}

	@Test
	public void getWhenUsingCustomAuthenticationManagerThenUsesItAccordingly() {
		this.spring.register(CustomAuthenticationManagerConfig.class).autowire();
		ReactiveAuthenticationManager authenticationManager = this.spring.getContext()
			.getBean(ReactiveAuthenticationManager.class);
		given(authenticationManager.authenticate(any(Authentication.class)))
			.willReturn(Mono.error(new OAuth2AuthenticationException(new OAuth2Error("mock-failure"))));
		// @formatter:off
		this.client.get()
				.headers((headers) -> headers
						.setBearerAuth(this.messageReadToken)
				)
				.exchange()
				.expectStatus().isUnauthorized()
				.expectHeader().value(HttpHeaders.WWW_AUTHENTICATE, startsWith("Bearer error=\"mock-failure\""));
		// @formatter:on
	}

	@Test
	public void getWhenUsingCustomAuthenticationManagerInLambdaThenUsesItAccordingly() {
		this.spring.register(CustomAuthenticationManagerInLambdaConfig.class).autowire();
		ReactiveAuthenticationManager authenticationManager = this.spring.getContext()
			.getBean(ReactiveAuthenticationManager.class);
		given(authenticationManager.authenticate(any(Authentication.class)))
			.willReturn(Mono.error(new OAuth2AuthenticationException(new OAuth2Error("mock-failure"))));
		// @formatter:off
		this.client.get()
				.headers((headers) -> headers
						.setBearerAuth(this.messageReadToken)
				)
				.exchange()
				.expectStatus().isUnauthorized()
				.expectHeader().value(HttpHeaders.WWW_AUTHENTICATE, startsWith("Bearer error=\"mock-failure\""));
		// @formatter:on
	}

	@Test
	public void getWhenUsingCustomAuthenticationManagerResolverThenUsesItAccordingly() {
		this.spring.register(CustomAuthenticationManagerResolverConfig.class).autowire();
		ReactiveAuthenticationManagerResolver<ServerWebExchange> authenticationManagerResolver = this.spring
			.getContext()
			.getBean(ReactiveAuthenticationManagerResolver.class);
		ReactiveAuthenticationManager authenticationManager = this.spring.getContext()
			.getBean(ReactiveAuthenticationManager.class);
		given(authenticationManagerResolver.resolve(any(ServerWebExchange.class)))
			.willReturn(Mono.just(authenticationManager));
		given(authenticationManager.authenticate(any(Authentication.class)))
			.willReturn(Mono.error(new OAuth2AuthenticationException(new OAuth2Error("mock-failure"))));
		// @formatter:off
		this.client.get()
				.headers((headers) -> headers
						.setBearerAuth(this.messageReadToken)
				)
				.exchange()
				.expectStatus().isUnauthorized()
				.expectHeader().value(HttpHeaders.WWW_AUTHENTICATE, startsWith("Bearer error=\"mock-failure\""));
		// @formatter:on
	}

	@Test
	public void getWhenUsingCustomAuthenticationFailureHandlerThenUsesIsAccordingly() {
		this.spring.register(CustomAuthenticationFailureHandlerConfig.class).autowire();
		ServerAuthenticationFailureHandler handler = this.spring.getContext()
			.getBean(ServerAuthenticationFailureHandler.class);
		ReactiveAuthenticationManager authenticationManager = this.spring.getContext()
			.getBean(ReactiveAuthenticationManager.class);
		given(authenticationManager.authenticate(any()))
			.willReturn(Mono.error(() -> new BadCredentialsException("bad")));
		given(handler.onAuthenticationFailure(any(), any())).willReturn(Mono.empty());
		// @formatter:off
		this.client.get()
				.headers((headers) -> headers.setBearerAuth(this.messageReadToken))
				.exchange()
				.expectStatus().isOk();
		// @formatter:on
		verify(handler).onAuthenticationFailure(any(), any());
	}

	@Test
	public void postWhenSignedThenReturnsOk() {
		this.spring.register(PublicKeyConfig.class, RootController.class).autowire();
		// @formatter:off
		this.client.post()
				.headers((headers) -> headers
						.setBearerAuth(this.messageReadToken)
				)
				.exchange()
				.expectStatus().isOk();
		// @formatter:on
	}

	@Test
	public void getWhenTokenHasInsufficientScopeThenReturnsInsufficientScope() {
		this.spring.register(DenyAllConfig.class, RootController.class).autowire();
		// @formatter:off
		this.client.get()
				.headers((headers) -> headers
						.setBearerAuth(this.messageReadToken)
				)
				.exchange()
				.expectStatus().isForbidden()
				.expectHeader().value(HttpHeaders.WWW_AUTHENTICATE, startsWith("Bearer error=\"insufficient_scope\""));
		// @formatter:on
	}

	@Test
	public void postWhenMissingTokenThenReturnsForbidden() {
		this.spring.register(PublicKeyConfig.class, RootController.class).autowire();
		// @formatter:off
		this.client.post()
				.exchange()
				.expectStatus().isForbidden();
		// @formatter:on
	}

	@Test
	public void getWhenCustomBearerTokenServerAuthenticationConverterThenResponds() {
		this.spring.register(CustomBearerTokenServerAuthenticationConverter.class, RootController.class).autowire();
		// @formatter:off
		this.client.get()
				.cookie("TOKEN", this.messageReadToken)
				.exchange()
				.expectStatus().isOk();
		// @formatter:on
	}

	@Test
	public void getWhenSignedAndCustomConverterThenConverts() {
		this.spring.register(CustomJwtAuthenticationConverterConfig.class, RootController.class).autowire();
		// @formatter:off
		this.client.get()
				.headers((headers) -> headers
						.setBearerAuth(this.messageReadToken)
				)
				.exchange()
				.expectStatus().isOk();
		// @formatter:on
	}

	@Test
	public void getWhenCustomBearerTokenEntryPointThenResponds() {
		this.spring.register(CustomErrorHandlingConfig.class).autowire();
		// @formatter:off
		this.client.get()
				.uri("/authenticated")
				.exchange()
				.expectStatus().isEqualTo(HttpStatus.I_AM_A_TEAPOT);
		// @formatter:on
	}

	@Test
	public void getWhenCustomBearerTokenDeniedHandlerThenResponds() {
		this.spring.register(CustomErrorHandlingConfig.class).autowire();
		// @formatter:off
		this.client.get()
				.uri("/unobtainable")
				.headers((headers) -> headers
						.setBearerAuth(this.messageReadToken)
				)
				.exchange()
				.expectStatus().isEqualTo(HttpStatus.BANDWIDTH_LIMIT_EXCEEDED);
		// @formatter:on
	}

	@Test
	public void getJwtDecoderWhenBeanWiredAndDslWiredThenDslTakesPrecedence() {
		GenericWebApplicationContext context = autowireWebServerGenericWebApplicationContext();
		ServerHttpSecurity http = new ServerHttpSecurity();
		http.setApplicationContext(context);
		ReactiveJwtDecoder beanWiredJwtDecoder = mock(ReactiveJwtDecoder.class);
		ReactiveJwtDecoder dslWiredJwtDecoder = mock(ReactiveJwtDecoder.class);
		context.registerBean(ReactiveJwtDecoder.class, () -> beanWiredJwtDecoder);
		http.oauth2ResourceServer((server) -> server.jwt((jwt) -> {
			jwt.jwtDecoder(dslWiredJwtDecoder);
			assertThat(jwt.getJwtDecoder()).isEqualTo(dslWiredJwtDecoder);
		}));
	}

	@Test
	public void getJwtDecoderWhenTwoBeansWiredAndDslWiredThenDslTakesPrecedence() {
		GenericWebApplicationContext context = autowireWebServerGenericWebApplicationContext();
		ServerHttpSecurity http = new ServerHttpSecurity();
		http.setApplicationContext(context);
		ReactiveJwtDecoder beanWiredJwtDecoder = mock(ReactiveJwtDecoder.class);
		ReactiveJwtDecoder dslWiredJwtDecoder = mock(ReactiveJwtDecoder.class);
		context.registerBean("firstJwtDecoder", ReactiveJwtDecoder.class, () -> beanWiredJwtDecoder);
		context.registerBean("secondJwtDecoder", ReactiveJwtDecoder.class, () -> beanWiredJwtDecoder);
		http.oauth2ResourceServer((server) -> server.jwt((jwt) -> {
			jwt.jwtDecoder(dslWiredJwtDecoder);
			assertThat(jwt.getJwtDecoder()).isEqualTo(dslWiredJwtDecoder);
		}));
	}

	@Test
	public void getJwtDecoderWhenTwoBeansWiredThenThrowsWiringException() {
		GenericWebApplicationContext context = autowireWebServerGenericWebApplicationContext();
		ServerHttpSecurity http = new ServerHttpSecurity();
		http.setApplicationContext(context);
		ReactiveJwtDecoder beanWiredJwtDecoder = mock(ReactiveJwtDecoder.class);
		context.registerBean("firstJwtDecoder", ReactiveJwtDecoder.class, () -> beanWiredJwtDecoder);
		context.registerBean("secondJwtDecoder", ReactiveJwtDecoder.class, () -> beanWiredJwtDecoder);
		http.oauth2ResourceServer(
				(server) -> server.jwt((jwt) -> assertThatExceptionOfType(NoUniqueBeanDefinitionException.class)
					.isThrownBy(jwt::getJwtDecoder)));
	}

	@Test
	public void getJwtDecoderWhenNoBeansAndNoDslWiredThenWiringException() {
		GenericWebApplicationContext context = autowireWebServerGenericWebApplicationContext();
		ServerHttpSecurity http = new ServerHttpSecurity();
		http.setApplicationContext(context);
		http.oauth2ResourceServer(
				(server) -> server.jwt((jwt) -> assertThatExceptionOfType(NoSuchBeanDefinitionException.class)
					.isThrownBy(jwt::getJwtDecoder)));
	}

	@Test
	public void getJwtAuthenticationConverterWhenBeanWiredAndDslWiredThenDslTakesPrecedence() {
		GenericWebApplicationContext context = autowireWebServerGenericWebApplicationContext();
		ServerHttpSecurity http = new ServerHttpSecurity();
		http.setApplicationContext(context);
		ReactiveJwtAuthenticationConverter beanWiredJwtAuthenticationConverter = new ReactiveJwtAuthenticationConverter();
		ReactiveJwtAuthenticationConverter dslWiredJwtAuthenticationConverter = new ReactiveJwtAuthenticationConverter();
		context.registerBean(ReactiveJwtAuthenticationConverter.class, () -> beanWiredJwtAuthenticationConverter);
		http.oauth2ResourceServer((server) -> server.jwt((jwt) -> {
			jwt.jwtAuthenticationConverter(dslWiredJwtAuthenticationConverter);
			assertThat(jwt.getJwtAuthenticationConverter()).isEqualTo(dslWiredJwtAuthenticationConverter);
		}));
	}

	@Test
	public void getJwtAuthenticationConverterWhenTwoBeansWiredAndDslWiredThenDslTakesPrecedence() {
		GenericWebApplicationContext context = autowireWebServerGenericWebApplicationContext();
		ServerHttpSecurity http = new ServerHttpSecurity();
		http.setApplicationContext(context);
		ReactiveJwtAuthenticationConverter beanWiredJwtAuthenticationConverter = new ReactiveJwtAuthenticationConverter();
		ReactiveJwtAuthenticationConverter dslWiredJwtAuthenticationConverter = new ReactiveJwtAuthenticationConverter();
		context.registerBean("firstJwtAuthenticationConverter", ReactiveJwtAuthenticationConverter.class,
				() -> beanWiredJwtAuthenticationConverter);
		context.registerBean("secondJwtAuthenticationConverter", ReactiveJwtAuthenticationConverter.class,
				() -> beanWiredJwtAuthenticationConverter);
		http.oauth2ResourceServer((server) -> server.jwt((jwt) -> {
			jwt.jwtAuthenticationConverter(dslWiredJwtAuthenticationConverter);
			assertThat(jwt.getJwtAuthenticationConverter()).isEqualTo(dslWiredJwtAuthenticationConverter);
		}));
	}

	@Test
	public void getJwtAuthenticationConverterWhenTwoBeansWiredThenThrowsWiringException() {
		GenericWebApplicationContext context = autowireWebServerGenericWebApplicationContext();
		ServerHttpSecurity http = new ServerHttpSecurity();
		http.setApplicationContext(context);
		ReactiveJwtAuthenticationConverter beanWiredJwtAuthenticationConverter = new ReactiveJwtAuthenticationConverter();
		context.registerBean("firstJwtAuthenticationConverter", ReactiveJwtAuthenticationConverter.class,
				() -> beanWiredJwtAuthenticationConverter);
		context.registerBean("secondJwtAuthenticationConverter", ReactiveJwtAuthenticationConverter.class,
				() -> beanWiredJwtAuthenticationConverter);
		http.oauth2ResourceServer(
				(server) -> server.jwt((jwt) -> assertThatExceptionOfType(NoUniqueBeanDefinitionException.class)
					.isThrownBy(jwt::getJwtAuthenticationConverter)));
	}

	@Test
	public void getJwtAuthenticationConverterWhenNoBeansAndNoDslWiredThenDefaultConverter() {
		GenericWebApplicationContext context = autowireWebServerGenericWebApplicationContext();
		ServerHttpSecurity http = new ServerHttpSecurity();
		http.setApplicationContext(context);
		http.oauth2ResourceServer((server) -> server.jwt((jwt) -> assertThat(jwt.getJwtAuthenticationConverter())
			.isInstanceOf(ReactiveJwtAuthenticationConverter.class)));
	}

	@Test
	public void introspectWhenValidThenReturnsOk() {
		this.spring.register(IntrospectionConfig.class, RootController.class).autowire();
		this.spring.getContext()
			.getBean(MockWebServer.class)
			.setDispatcher(requiresAuth(this.clientId, this.clientSecret, this.active));
		// @formatter:off
		this.client.get()
				.headers((headers) -> headers
						.setBearerAuth(this.messageReadToken)
				)
				.exchange()
				.expectStatus().isOk();
		// @formatter:on
	}

	@Test
	public void introspectWhenValidAndIntrospectionInLambdaThenReturnsOk() {
		this.spring.register(IntrospectionInLambdaConfig.class, RootController.class).autowire();
		this.spring.getContext()
			.getBean(MockWebServer.class)
			.setDispatcher(requiresAuth(this.clientId, this.clientSecret, this.active));
		// @formatter:off
		this.client.get()
				.headers((headers) -> headers
						.setBearerAuth(this.messageReadToken)
				)
				.exchange()
				.expectStatus().isOk();
		// @formatter:on
	}

	@Test
	public void configureWhenUsingBothAuthenticationManagerResolverAndOpaqueThenWiringException() {
		assertThatExceptionOfType(BeanCreationException.class)
			.isThrownBy(() -> this.spring.register(AuthenticationManagerResolverPlusOtherConfig.class).autowire())
			.withMessageContaining("authenticationManagerResolver");
	}

	@Test
	public void getWhenCustomAuthenticationConverterThenConverts() {
		this.spring.register(ReactiveOpaqueTokenAuthenticationConverterConfig.class, RootController.class).autowire();
		this.spring.getContext()
			.getBean(MockWebServer.class)
			.setDispatcher(requiresAuth(this.clientId, this.clientSecret, this.active));
		ReactiveOpaqueTokenAuthenticationConverter authenticationConverter = this.spring.getContext()
			.getBean(ReactiveOpaqueTokenAuthenticationConverter.class);
		given(authenticationConverter.convert(anyString(), any(OAuth2AuthenticatedPrincipal.class)))
			.willReturn(Mono.just(new TestingAuthenticationToken("jdoe", null, Collections.emptyList())));
		// @formatter:off
		this.client.get()
				.headers((headers) -> headers
						.setBearerAuth(this.messageReadToken)
				)
				.exchange()
				.expectStatus().isOk();
		// @formatter:on
	}

	private static Dispatcher requiresAuth(String username, String password, String response) {
		return new Dispatcher() {
			@Override
			public MockResponse dispatch(RecordedRequest request) {
				String authorization = request.getHeader(org.springframework.http.HttpHeaders.AUTHORIZATION);
				// @formatter:off
				return Optional.ofNullable(authorization)
						.filter((a) -> isAuthorized(authorization, username, password))
						.map((a) -> ok(response))
						.orElse(unauthorized());
				// @formatter:on
			}
		};
	}

	private static boolean isAuthorized(String authorization, String username, String password) {
		String[] values = new String(Base64.getDecoder().decode(authorization.substring(6))).split(":");
		return username.equals(values[0]) && password.equals(values[1]);
	}

	private static MockResponse ok(String response) {
		return new MockResponse().setBody(response)
			.setHeader(org.springframework.http.HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
	}

	private static MockResponse unauthorized() {
		return new MockResponse().setResponseCode(401);
	}

	private static RSAPublicKey publicKey() {
		String modulus = "26323220897278656456354815752829448539647589990395639665273015355787577386000316054335559633864476469390247312823732994485311378484154955583861993455004584140858982659817218753831620205191028763754231454775026027780771426040997832758235764611119743390612035457533732596799927628476322029280486807310749948064176545712270582940917249337311592011920620009965129181413510845780806191965771671528886508636605814099711121026468495328702234901200169245493126030184941412539949521815665744267183140084667383643755535107759061065656273783542590997725982989978433493861515415520051342321336460543070448417126615154138673620797";
		String exponent = "65537";
		RSAPublicKeySpec spec = new RSAPublicKeySpec(new BigInteger(modulus), new BigInteger(exponent));
		RSAPublicKey rsaPublicKey = null;
		try {
			KeyFactory factory = KeyFactory.getInstance("RSA");
			rsaPublicKey = (RSAPublicKey) factory.generatePublic(spec);
		}
		catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
			ex.printStackTrace();
		}
		return rsaPublicKey;
	}

	private GenericWebApplicationContext autowireWebServerGenericWebApplicationContext() {
		GenericWebApplicationContext context = new GenericWebApplicationContext();
		context.registerBean("webHandler", DispatcherHandler.class);
		this.spring.context(context).autowire();
		return (GenericWebApplicationContext) this.spring.getContext();
	}

	@Configuration
	@EnableWebFlux
	@EnableWebFluxSecurity
	static class PublicKeyConfig {

		@Bean
		SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
			// @formatter:off
			http
				.authorizeExchange((authorize) -> authorize
					.anyExchange().hasAuthority("SCOPE_message:read"))
				.oauth2ResourceServer((server) -> server
					.jwt((jwt) -> jwt.publicKey(publicKey())));
			// @formatter:on
			return http.build();
		}

	}

	@Configuration
	@EnableWebFlux
	@EnableWebFluxSecurity
	static class PublicKeyInLambdaConfig {

		@Bean
		SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
			// @formatter:off
			http
				.authorizeExchange((authorize) -> authorize
						.anyExchange().hasAuthority("SCOPE_message:read")
				)
				.oauth2ResourceServer((oauth2) -> oauth2
						.jwt((jwt) -> jwt
								.publicKey(publicKey())
						)
				);
			// @formatter:on
			return http.build();
		}

	}

	@Configuration
	@EnableWebFlux
	@EnableWebFluxSecurity
	static class PlaceholderConfig {

		@Value("classpath:org/springframework/security/config/web/server/OAuth2ResourceServerSpecTests-simple.pub")
		RSAPublicKey key;

		@Bean
		SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
			// @formatter:off
			http
				.authorizeExchange((authorize) -> authorize
					.anyExchange().hasAuthority("SCOPE_message:read"))
				.oauth2ResourceServer((server) -> server
					.jwt((jwt) -> jwt.publicKey(this.key)));
			// @formatter:on
			return http.build();
		}

	}

	@Configuration
	@EnableWebFlux
	@EnableWebFluxSecurity
	static class JwkSetUriConfig {

		private MockWebServer mockWebServer = new MockWebServer();

		@Bean
		SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
			String jwkSetUri = mockWebServer().url("/.well-known/jwks.json").toString();
			// @formatter:off
			http
				.oauth2ResourceServer((server) -> server
					.jwt((jwt) -> jwt.jwkSetUri(jwkSetUri)));
			// @formatter:on
			return http.build();
		}

		@Bean
		MockWebServer mockWebServer() {
			return this.mockWebServer;
		}

		@PreDestroy
		void shutdown() throws IOException {
			this.mockWebServer.shutdown();
		}

	}

	@Configuration
	@EnableWebFlux
	@EnableWebFluxSecurity
	static class JwkSetUriInLambdaConfig {

		private MockWebServer mockWebServer = new MockWebServer();

		@Bean
		SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
			String jwkSetUri = mockWebServer().url("/.well-known/jwks.json").toString();
			// @formatter:off
			http
				.oauth2ResourceServer((oauth2) -> oauth2
						.jwt((jwt) -> jwt
								.jwkSetUri(jwkSetUri)
						)
				);
			// @formatter:on
			return http.build();
		}

		@Bean
		MockWebServer mockWebServer() {
			return this.mockWebServer;
		}

		@PreDestroy
		void shutdown() throws IOException {
			this.mockWebServer.shutdown();
		}

	}

	@Configuration
	@EnableWebFlux
	@EnableWebFluxSecurity
	static class CustomDecoderConfig {

		ReactiveJwtDecoder jwtDecoder = mock(ReactiveJwtDecoder.class);

		@Bean
		SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
			// @formatter:off
			http
				.oauth2ResourceServer((server) -> server
					.jwt(Customizer.withDefaults()));
			// @formatter:on
			return http.build();
		}

		@Bean
		ReactiveJwtDecoder jwtDecoder() {
			return this.jwtDecoder;
		}

	}

	@Configuration
	@EnableWebFlux
	@EnableWebFluxSecurity
	static class DenyAllConfig {

		@Bean
		SecurityWebFilterChain authorization(ServerHttpSecurity http) {
			// @formatter:off
			http
				.authorizeExchange((authorize) -> authorize
					.anyExchange().denyAll())
				.oauth2ResourceServer((server) -> server
					.jwt((jwt) -> jwt.publicKey(publicKey())));
			// @formatter:on
			return http.build();
		}

	}

	@Configuration
	@EnableWebFlux
	@EnableWebFluxSecurity
	static class CustomAuthenticationManagerConfig {

		@Bean
		SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
			// @formatter:off
			http
				.oauth2ResourceServer((server) -> server
					.jwt((jwt) -> jwt.authenticationManager(authenticationManager())));
			// @formatter:on
			return http.build();
		}

		@Bean
		ReactiveAuthenticationManager authenticationManager() {
			return mock(ReactiveAuthenticationManager.class);
		}

	}

	@Configuration
	@EnableWebFlux
	@EnableWebFluxSecurity
	static class CustomAuthenticationManagerInLambdaConfig {

		@Bean
		SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
			// @formatter:off
			http
				.oauth2ResourceServer((oauth2) -> oauth2
						.jwt((jwt) -> jwt
								.authenticationManager(authenticationManager())
						)
				);
			// @formatter:on
			return http.build();
		}

		@Bean
		ReactiveAuthenticationManager authenticationManager() {
			return mock(ReactiveAuthenticationManager.class);
		}

	}

	@Configuration
	@EnableWebFlux
	@EnableWebFluxSecurity
	static class CustomAuthenticationManagerResolverConfig {

		@Bean
		SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
			// @formatter:off
			http
				.authorizeExchange((authorize) -> authorize
					.pathMatchers("/*/message/**").hasAnyAuthority("SCOPE_message:read"))
				.oauth2ResourceServer((server) -> server
					.authenticationManagerResolver(authenticationManagerResolver()));
			// @formatter:on
			return http.build();
		}

		@Bean
		ReactiveAuthenticationManagerResolver<ServerWebExchange> authenticationManagerResolver() {
			return mock(ReactiveAuthenticationManagerResolver.class);
		}

		@Bean
		ReactiveAuthenticationManager authenticationManager() {
			return mock(ReactiveAuthenticationManager.class);
		}

	}

	@Configuration
	@EnableWebFlux
	@EnableWebFluxSecurity
	static class CustomAuthenticationFailureHandlerConfig {

		@Bean
		SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
			// @formatter:off
			http
				.authorizeExchange((authorize) -> authorize.anyExchange().authenticated())
				.oauth2ResourceServer((oauth2) -> oauth2
					.authenticationFailureHandler(authenticationFailureHandler())
					.jwt((jwt) -> jwt.authenticationManager(authenticationManager()))
				);
			// @formatter:on
			return http.build();
		}

		@Bean
		ReactiveAuthenticationManager authenticationManager() {
			return mock(ReactiveAuthenticationManager.class);
		}

		@Bean
		ServerAuthenticationFailureHandler authenticationFailureHandler() {
			return mock(ServerAuthenticationFailureHandler.class);
		}

	}

	@EnableWebFlux
	@EnableWebFluxSecurity
	static class CustomBearerTokenServerAuthenticationConverter {

		@Bean
		SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
			// @formatter:off
			http
				.authorizeExchange((authorize) -> authorize
					.anyExchange().hasAuthority("SCOPE_message:read"))
				.oauth2ResourceServer((server) -> server
					.bearerTokenConverter(bearerTokenAuthenticationConverter())
					.jwt((jwt) -> jwt.publicKey(publicKey())));
			// @formatter:on
			return http.build();
		}

		@Bean
		ServerAuthenticationConverter bearerTokenAuthenticationConverter() {
			return (exchange) -> Mono.justOrEmpty(exchange.getRequest().getCookies().getFirst("TOKEN").getValue())
				.map(BearerTokenAuthenticationToken::new);
		}

	}

	@Configuration
	@EnableWebFlux
	@EnableWebFluxSecurity
	static class CustomJwtAuthenticationConverterConfig {

		@Bean
		SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
			// @formatter:off
			http
				.authorizeExchange((authorize) -> authorize
					.anyExchange().hasAuthority("message:read"))
				.oauth2ResourceServer((server) -> server
					.jwt((jwt) -> jwt
						.jwtAuthenticationConverter(jwtAuthenticationConverter())
						.publicKey(publicKey())));
			// @formatter:on
			return http.build();
		}

		@Bean
		Converter<Jwt, Mono<AbstractAuthenticationToken>> jwtAuthenticationConverter() {
			JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
			converter.setJwtGrantedAuthoritiesConverter((jwt) -> {
				String[] claims = ((String) jwt.getClaims().get("scope")).split(" ");
				return Stream.of(claims).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
			});
			return new ReactiveJwtAuthenticationConverterAdapter(converter);
		}

	}

	@Configuration
	@EnableWebFlux
	@EnableWebFluxSecurity
	static class CustomErrorHandlingConfig {

		@Bean
		SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
			// @formatter:off
			http
				.authorizeExchange((authorize) -> authorize
					.pathMatchers("/authenticated").authenticated()
					.pathMatchers("/unobtainable").hasAuthority("unobtainable"))
				.oauth2ResourceServer((server) -> server
					.accessDeniedHandler(new HttpStatusServerAccessDeniedHandler(HttpStatus.BANDWIDTH_LIMIT_EXCEEDED))
					.authenticationEntryPoint(new HttpStatusServerEntryPoint(HttpStatus.I_AM_A_TEAPOT))
					.jwt((jwt) -> jwt.publicKey(publicKey())));
			// @formatter:on
			return http.build();
		}

	}

	@Configuration
	@EnableWebFlux
	@EnableWebFluxSecurity
	static class IntrospectionConfig {

		private MockWebServer mockWebServer = new MockWebServer();

		@Bean
		SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
			String introspectionUri = mockWebServer().url("/introspect").toString();
			// @formatter:off
			http
				.oauth2ResourceServer((server) -> server
					.opaqueToken((opaqueToken) -> opaqueToken
						.introspectionUri(introspectionUri)
						.introspectionClientCredentials("client", "secret")));
			// @formatter:on
			return http.build();
		}

		@Bean
		MockWebServer mockWebServer() {
			return this.mockWebServer;
		}

		@PreDestroy
		void shutdown() throws IOException {
			this.mockWebServer.shutdown();
		}

	}

	@Configuration
	@EnableWebFlux
	@EnableWebFluxSecurity
	static class IntrospectionInLambdaConfig {

		private MockWebServer mockWebServer = new MockWebServer();

		@Bean
		SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
			String introspectionUri = mockWebServer().url("/introspect").toString();
			// @formatter:off
			http
				.oauth2ResourceServer((oauth2) -> oauth2
						.opaqueToken((opaqueToken) -> opaqueToken
									.introspectionUri(introspectionUri)
									.introspectionClientCredentials("client", "secret")
						)
				);
			// @formatter:on
			return http.build();
		}

		@Bean
		MockWebServer mockWebServer() {
			return this.mockWebServer;
		}

		@PreDestroy
		void shutdown() throws IOException {
			this.mockWebServer.shutdown();
		}

	}

	@Configuration
	@EnableWebFlux
	@EnableWebFluxSecurity
	static class AuthenticationManagerResolverPlusOtherConfig {

		@Bean
		SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
			// @formatter:off
			http
				.authorizeExchange((authorize) -> authorize
					.anyExchange().authenticated())
				.oauth2ResourceServer((server) -> server
					.authenticationManagerResolver(mock(ReactiveAuthenticationManagerResolver.class))
					.opaqueToken(Customizer.withDefaults()));
			// @formatter:on
			return http.build();
		}

	}

	@Configuration
	@EnableWebFlux
	@EnableWebFluxSecurity
	static class ReactiveOpaqueTokenAuthenticationConverterConfig {

		private MockWebServer mockWebServer = new MockWebServer();

		@Bean
		SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
			String introspectionUri = mockWebServer().url("/introspect").toString();
			// @formatter:off
			http
				.oauth2ResourceServer((server) -> server
					.opaqueToken((opaqueToken) -> opaqueToken
						.introspectionUri(introspectionUri)
						.introspectionClientCredentials("client", "secret")
						.authenticationConverter(authenticationConverter())));
			// @formatter:on
			return http.build();
		}

		@Bean
		ReactiveOpaqueTokenAuthenticationConverter authenticationConverter() {
			return mock(ReactiveOpaqueTokenAuthenticationConverter.class);
		}

		@Bean
		MockWebServer mockWebServer() {
			return this.mockWebServer;
		}

		@PreDestroy
		void shutdown() throws IOException {
			this.mockWebServer.shutdown();
		}

	}

	@RestController
	static class RootController {

		@GetMapping
		Mono<String> get() {
			return Mono.just("ok");
		}

		@PostMapping
		Mono<String> post() {
			return Mono.just("ok");
		}

	}

}
