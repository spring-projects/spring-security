/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.oauth2.client.endpoint;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.util.Set;
import java.util.function.Consumer;

import static org.springframework.security.oauth2.core.web.reactive.function.OAuth2BodyExtractors.oauth2AccessTokenResponse;

/**
 * An implementation of an {@link ReactiveOAuth2AccessTokenResponseClient} that &quot;exchanges&quot;
 * an authorization code credential for an access token credential
 * at the Authorization Server's Token Endpoint.
 *
 * @author Rob Winch
 * @since 5.1
 * @see OAuth2AccessTokenResponseClient
 * @see OAuth2AuthorizationCodeGrantRequest
 * @see OAuth2AccessTokenResponse
 * @see <a target="_blank" href="https://connect2id.com/products/nimbus-oauth-openid-connect-sdk">Nimbus OAuth 2.0 SDK</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.3">Section 4.1.3 Access Token Request (Authorization Code Grant)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.4">Section 4.1.4 Access Token Response (Authorization Code Grant)</a>
 */
public class WebClientReactiveClientCredentialsTokenResponseClient implements ReactiveOAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> {
	private WebClient webClient = WebClient.builder()
			.build();

	@Override
	public Mono<OAuth2AccessTokenResponse> getTokenResponse(OAuth2ClientCredentialsGrantRequest authorizationGrantRequest) {
		return Mono.defer(() -> {
			ClientRegistration clientRegistration = authorizationGrantRequest.getClientRegistration();

			String tokenUri = clientRegistration.getProviderDetails().getTokenUri();
			BodyInserters.FormInserter<String> body = body(authorizationGrantRequest);

			return this.webClient.post()
					.uri(tokenUri)
					.accept(MediaType.APPLICATION_JSON)
					.headers(headers(clientRegistration))
					.body(body)
					.exchange()
					.flatMap(response ->{
						if (!response.statusCode().is2xxSuccessful()){
							// extract the contents of this into a method named oauth2AccessTokenResponse but has an argument for the response
							throw WebClientResponseException.create(response.rawStatusCode(),
											"Cannot get token, expected 2xx HTTP Status code",
											null,
											null,
											null
									);
						}
						return response.body(oauth2AccessTokenResponse()); })
					.map(response -> {
						if (response.getAccessToken().getScopes().isEmpty()) {
							response = OAuth2AccessTokenResponse.withResponse(response)
								.scopes(authorizationGrantRequest.getClientRegistration().getScopes())
								.build();
						}
						return response;
					});
		});
	}

	private Consumer<HttpHeaders> headers(ClientRegistration clientRegistration) {
		return headers -> {
			headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
			headers.setBasicAuth(clientRegistration.getClientId(), clientRegistration.getClientSecret());
			if (ClientAuthenticationMethod.BASIC.equals(clientRegistration.getClientAuthenticationMethod())) {
				headers.setBasicAuth(clientRegistration.getClientId(), clientRegistration.getClientSecret());
			}
		};
	}

	private static BodyInserters.FormInserter<String> body(OAuth2ClientCredentialsGrantRequest authorizationGrantRequest) {
		ClientRegistration clientRegistration = authorizationGrantRequest.getClientRegistration();
		BodyInserters.FormInserter<String> body = BodyInserters
				.fromFormData(OAuth2ParameterNames.GRANT_TYPE, authorizationGrantRequest.getGrantType().getValue());
		Set<String> scopes = clientRegistration.getScopes();
		if (!CollectionUtils.isEmpty(scopes)) {
			String scope = StringUtils.collectionToDelimitedString(scopes, " ");
			body.with(OAuth2ParameterNames.SCOPE, scope);
		}
		if (ClientAuthenticationMethod.POST.equals(clientRegistration.getClientAuthenticationMethod())) {
			body.with(OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId());
			body.with(OAuth2ParameterNames.CLIENT_SECRET, clientRegistration.getClientSecret());
		}
		return body;
	}
}
