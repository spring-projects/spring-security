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

package org.springframework.security.oauth2.client.web.server;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

/**
 * @author Rob Winch
 * @since 5.1
 */
@RunWith(MockitoJUnitRunner.class)
public class DefaultServerOAuth2AuthorizationRequestResolverTests {

	@Mock
	private ReactiveClientRegistrationRepository clientRegistrationRepository;

	private DefaultServerOAuth2AuthorizationRequestResolver resolver;

	private ClientRegistration registration = TestClientRegistrations.clientRegistration().build();

	@Before
	public void setup() {
		this.resolver = new DefaultServerOAuth2AuthorizationRequestResolver(this.clientRegistrationRepository);
	}

	@Test
	public void setAuthorizationRequestCustomizerWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.resolver.setAuthorizationRequestCustomizer(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void resolveWhenNotMatchThenNull() {
		assertThat(resolve("/")).isNull();
	}

	@Test
	public void resolveWhenClientRegistrationNotFoundMatchThenBadRequest() {
		given(this.clientRegistrationRepository.findByRegistrationId(any())).willReturn(Mono.empty());

		ResponseStatusException expected = catchThrowableOfType(() -> resolve("/oauth2/authorization/not-found-id"),
				ResponseStatusException.class);

		assertThat(expected.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
	}

	@Test
	public void resolveWhenClientRegistrationFoundThenWorks() {
		given(this.clientRegistrationRepository.findByRegistrationId(any())).willReturn(Mono.just(this.registration));

		OAuth2AuthorizationRequest request = resolve("/oauth2/authorization/not-found-id");

		assertThat(request.getAuthorizationRequestUri())
				.matches("https://example.com/login/oauth/authorize\\?" + "response_type=code&client_id=client-id&"
						+ "scope=read:user&state=.*?&" + "redirect_uri=/login/oauth2/code/registration-id");
	}

	@Test
	public void resolveWhenForwardedHeadersClientRegistrationFoundThenWorks() {
		given(this.clientRegistrationRepository.findByRegistrationId(any())).willReturn(Mono.just(this.registration));
		ServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.get("/oauth2/authorization/id").header("X-Forwarded-Host", "evil.com"));

		OAuth2AuthorizationRequest request = this.resolver.resolve(exchange).block();

		assertThat(request.getAuthorizationRequestUri())
				.matches("https://example.com/login/oauth/authorize\\?" + "response_type=code&client_id=client-id&"
						+ "scope=read:user&state=.*?&" + "redirect_uri=/login/oauth2/code/registration-id");
	}

	@Test
	public void resolveWhenAuthorizationRequestWithValidPkceClientThenResolves() {
		given(this.clientRegistrationRepository.findByRegistrationId(any()))
				.willReturn(Mono.just(TestClientRegistrations.clientRegistration()
						.clientAuthenticationMethod(ClientAuthenticationMethod.NONE).clientSecret(null).build()));

		OAuth2AuthorizationRequest request = resolve("/oauth2/authorization/registration-id");

		assertThat((String) request.getAttribute(PkceParameterNames.CODE_VERIFIER))
				.matches("^([a-zA-Z0-9\\-\\.\\_\\~]){128}$");

		assertThat(request.getAuthorizationRequestUri())
				.matches("https://example.com/login/oauth/authorize\\?" + "response_type=code&client_id=client-id&"
						+ "scope=read:user&state=.*?&" + "redirect_uri=/login/oauth2/code/registration-id&"
						+ "code_challenge_method=S256&" + "code_challenge=([a-zA-Z0-9\\-\\.\\_\\~]){43}");
	}

	@Test
	public void resolveWhenAuthenticationRequestWithValidOidcClientThenResolves() {
		given(this.clientRegistrationRepository.findByRegistrationId(any()))
				.willReturn(Mono.just(TestClientRegistrations.clientRegistration().scope(OidcScopes.OPENID).build()));

		OAuth2AuthorizationRequest request = resolve("/oauth2/authorization/registration-id");

		assertThat((String) request.getAttribute(OidcParameterNames.NONCE)).matches("^([a-zA-Z0-9\\-\\.\\_\\~]){128}$");

		assertThat(request.getAuthorizationRequestUri()).matches("https://example.com/login/oauth/authorize\\?"
				+ "response_type=code&client_id=client-id&" + "scope=openid&state=.*?&"
				+ "redirect_uri=/login/oauth2/code/registration-id&" + "nonce=([a-zA-Z0-9\\-\\.\\_\\~]){43}");
	}

	// gh-7696
	@Test
	public void resolveWhenAuthorizationRequestCustomizerRemovesNonceThenQueryExcludesNonce() {
		given(this.clientRegistrationRepository.findByRegistrationId(any()))
				.willReturn(Mono.just(TestClientRegistrations.clientRegistration().scope(OidcScopes.OPENID).build()));

		this.resolver.setAuthorizationRequestCustomizer(
				(customizer) -> customizer.additionalParameters((params) -> params.remove(OidcParameterNames.NONCE))
						.attributes((attrs) -> attrs.remove(OidcParameterNames.NONCE)));

		OAuth2AuthorizationRequest authorizationRequest = resolve("/oauth2/authorization/registration-id");

		assertThat(authorizationRequest.getAdditionalParameters()).doesNotContainKey(OidcParameterNames.NONCE);
		assertThat(authorizationRequest.getAttributes()).doesNotContainKey(OidcParameterNames.NONCE);
		assertThat(authorizationRequest.getAttributes()).containsKey(OAuth2ParameterNames.REGISTRATION_ID);
		assertThat(authorizationRequest.getAuthorizationRequestUri())
				.matches("https://example.com/login/oauth/authorize\\?" + "response_type=code&client_id=client-id&"
						+ "scope=openid&state=.{15,}&" + "redirect_uri=/login/oauth2/code/registration-id");
	}

	@Test
	public void resolveWhenAuthorizationRequestCustomizerAddsParameterThenQueryIncludesParameter() {
		given(this.clientRegistrationRepository.findByRegistrationId(any()))
				.willReturn(Mono.just(TestClientRegistrations.clientRegistration().scope(OidcScopes.OPENID).build()));

		this.resolver
				.setAuthorizationRequestCustomizer((customizer) -> customizer.authorizationRequestUri((uriBuilder) -> {
					uriBuilder.queryParam("param1", "value1");
					return uriBuilder.build();
				}));

		OAuth2AuthorizationRequest authorizationRequest = resolve("/oauth2/authorization/registration-id");

		assertThat(authorizationRequest.getAuthorizationRequestUri())
				.matches("https://example.com/login/oauth/authorize\\?" + "response_type=code&client_id=client-id&"
						+ "scope=openid&state=.{15,}&" + "redirect_uri=/login/oauth2/code/registration-id&"
						+ "nonce=([a-zA-Z0-9\\-\\.\\_\\~]){43}&" + "param1=value1");
	}

	@Test
	public void resolveWhenAuthorizationRequestCustomizerOverridesParameterThenQueryIncludesParameter() {
		given(this.clientRegistrationRepository.findByRegistrationId(any()))
				.willReturn(Mono.just(TestClientRegistrations.clientRegistration().scope(OidcScopes.OPENID).build()));

		this.resolver.setAuthorizationRequestCustomizer((customizer) -> customizer.parameters((params) -> {
			params.put("appid", params.get("client_id"));
			params.remove("client_id");
		}));

		OAuth2AuthorizationRequest authorizationRequest = resolve("/oauth2/authorization/registration-id");

		assertThat(authorizationRequest.getAuthorizationRequestUri())
				.matches("https://example.com/login/oauth/authorize\\?" + "response_type=code&"
						+ "scope=openid&state=.{15,}&" + "redirect_uri=/login/oauth2/code/registration-id&"
						+ "nonce=([a-zA-Z0-9\\-\\.\\_\\~]){43}&" + "appid=client-id");
	}

	private OAuth2AuthorizationRequest resolve(String path) {
		ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get(path));
		return this.resolver.resolve(exchange).block();
	}

}
