/*
 * Copyright 2002-2022 the original author or authors.
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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.entry;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;

/**
 * @author Rob Winch
 * @since 5.1
 */
@ExtendWith(MockitoExtension.class)
public class DefaultServerOAuth2AuthorizationRequestResolverTests {

	@Mock
	private ReactiveClientRegistrationRepository clientRegistrationRepository;

	private DefaultServerOAuth2AuthorizationRequestResolver resolver;

	private ClientRegistration registration = TestClientRegistrations.clientRegistration().build();

	@BeforeEach
	public void setup() {
		this.resolver = new DefaultServerOAuth2AuthorizationRequestResolver(this.clientRegistrationRepository);
	}

	@Test
	public void setAuthorizationRequestCustomizerWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.resolver.setAuthorizationRequestCustomizer(null));
	}

	@Test
	public void resolveWhenNotMatchThenNull() {
		assertThat(resolve("/")).isNull();
	}

	@Test
	public void resolveWhenClientRegistrationNotFoundMatchThenBadRequest() {
		given(this.clientRegistrationRepository.findByRegistrationId(any())).willReturn(Mono.empty());
		assertThatExceptionOfType(ResponseStatusException.class)
				.isThrownBy(() -> resolve("/oauth2/authorization/not-found-id"))
				.satisfies((ex) -> assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST));
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
		// @formatter:off
		MockServerHttpRequest.BaseBuilder<?> httpRequest = MockServerHttpRequest
				.get("/oauth2/authorization/id")
				.header("X-Forwarded-Host", "evil.com");
		// @formatter:on
		ServerWebExchange exchange = MockServerWebExchange.from(httpRequest);
		OAuth2AuthorizationRequest request = this.resolver.resolve(exchange).block();
		assertThat(request.getAuthorizationRequestUri())
				.matches("https://example.com/login/oauth/authorize\\?" + "response_type=code&client_id=client-id&"
						+ "scope=read:user&state=.*?&" + "redirect_uri=/login/oauth2/code/registration-id");
	}

	@Test
	public void resolveWhenAuthorizationRequestWithValidPublicClientThenResolves() {
		given(this.clientRegistrationRepository.findByRegistrationId(any()))
				.willReturn(Mono.just(TestClientRegistrations.clientRegistration()
						.clientAuthenticationMethod(ClientAuthenticationMethod.NONE).clientSecret(null).build()));
		OAuth2AuthorizationRequest request = resolve("/oauth2/authorization/registration-id");
		assertThat((String) request.getAttribute(PkceParameterNames.CODE_VERIFIER))
				.matches("^([a-zA-Z0-9\\-\\.\\_\\~]){128}$");
		assertThat(request.getAuthorizationRequestUri())
				.matches("https://example.com/login/oauth/authorize\\?" + "response_type=code&client_id=client-id&"
						+ "scope=read:user&state=.*?&" + "redirect_uri=/login/oauth2/code/registration-id&"
						+ "code_challenge=([a-zA-Z0-9\\-\\.\\_\\~]){43}&" + "code_challenge_method=S256");
	}

	// gh-6548
	@Test
	public void resolveWhenAuthorizationRequestApplyPkceToConfidentialClientsThenApplied() {
		ClientRegistration registration1 = TestClientRegistrations.clientRegistration().build();
		given(this.clientRegistrationRepository.findByRegistrationId(eq(registration1.getRegistrationId())))
				.willReturn(Mono.just(registration1));
		ClientRegistration registration2 = TestClientRegistrations.clientRegistration2().build();
		given(this.clientRegistrationRepository.findByRegistrationId(eq(registration2.getRegistrationId())))
				.willReturn(Mono.just(registration2));

		this.resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());

		OAuth2AuthorizationRequest request = resolve("/oauth2/authorization/" + registration1.getRegistrationId());
		assertPkceApplied(request, registration1);

		request = resolve("/oauth2/authorization/" + registration2.getRegistrationId());
		assertPkceApplied(request, registration2);
	}

	// gh-6548
	@Test
	public void resolveWhenAuthorizationRequestApplyPkceToSpecificConfidentialClientThenApplied() {
		ClientRegistration registration1 = TestClientRegistrations.clientRegistration().build();
		given(this.clientRegistrationRepository.findByRegistrationId(eq(registration1.getRegistrationId())))
				.willReturn(Mono.just(registration1));
		ClientRegistration registration2 = TestClientRegistrations.clientRegistration2().build();
		given(this.clientRegistrationRepository.findByRegistrationId(eq(registration2.getRegistrationId())))
				.willReturn(Mono.just(registration2));

		this.resolver.setAuthorizationRequestCustomizer((builder) -> {
			builder.attributes((attrs) -> {
				String registrationId = (String) attrs.get(OAuth2ParameterNames.REGISTRATION_ID);
				if (registration1.getRegistrationId().equals(registrationId)) {
					OAuth2AuthorizationRequestCustomizers.withPkce().accept(builder);
				}
			});
		});

		OAuth2AuthorizationRequest request = resolve("/oauth2/authorization/" + registration1.getRegistrationId());
		assertPkceApplied(request, registration1);

		request = resolve("/oauth2/authorization/" + registration2.getRegistrationId());
		assertPkceNotApplied(request, registration2);
	}

	private void assertPkceApplied(OAuth2AuthorizationRequest authorizationRequest,
			ClientRegistration clientRegistration) {
		assertThat(authorizationRequest.getAdditionalParameters()).containsKey(PkceParameterNames.CODE_CHALLENGE);
		assertThat(authorizationRequest.getAdditionalParameters())
				.contains(entry(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256"));
		assertThat(authorizationRequest.getAttributes()).containsKey(PkceParameterNames.CODE_VERIFIER);
		assertThat((String) authorizationRequest.getAttribute(PkceParameterNames.CODE_VERIFIER))
				.matches("^([a-zA-Z0-9\\-\\.\\_\\~]){128}$");
		assertThat(authorizationRequest.getAuthorizationRequestUri())
				.matches("https://example.com/login/oauth/authorize\\?" + "response_type=code&" + "client_id="
						+ clientRegistration.getClientId() + "&" + "scope=read:user&" + "state=.{15,}&"
						+ "redirect_uri=/login/oauth2/code/" + clientRegistration.getRegistrationId() + "&"
						+ "code_challenge=([a-zA-Z0-9\\-\\.\\_\\~]){43}&" + "code_challenge_method=S256");
	}

	private void assertPkceNotApplied(OAuth2AuthorizationRequest authorizationRequest,
			ClientRegistration clientRegistration) {
		assertThat(authorizationRequest.getAdditionalParameters()).doesNotContainKey(PkceParameterNames.CODE_CHALLENGE);
		assertThat(authorizationRequest.getAdditionalParameters())
				.doesNotContainKey(PkceParameterNames.CODE_CHALLENGE_METHOD);
		assertThat(authorizationRequest.getAttributes()).doesNotContainKey(PkceParameterNames.CODE_VERIFIER);
		assertThat(authorizationRequest.getAuthorizationRequestUri())
				.matches("https://example.com/login/oauth/authorize\\?" + "response_type=code&" + "client_id="
						+ clientRegistration.getClientId() + "&" + "scope=read:user&" + "state=.{15,}&"
						+ "redirect_uri=/login/oauth2/code/" + clientRegistration.getRegistrationId());
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
				(builder) -> builder.additionalParameters((params) -> params.remove(OidcParameterNames.NONCE))
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
		this.resolver.setAuthorizationRequestCustomizer((builder) -> builder.authorizationRequestUri((uriBuilder) -> {
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
		this.resolver.setAuthorizationRequestCustomizer((builder) -> builder.parameters((params) -> {
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
