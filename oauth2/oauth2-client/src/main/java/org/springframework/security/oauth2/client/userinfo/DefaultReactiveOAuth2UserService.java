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

package org.springframework.security.oauth2.client.userinfo;


import java.io.IOException;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.UnsupportedMediaTypeException;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;

import net.minidev.json.JSONObject;
import reactor.core.publisher.Mono;

/**
 * An implementation of an {@link ReactiveOAuth2UserService} that supports standard OAuth 2.0 Provider's.
 * <p>
 * For standard OAuth 2.0 Provider's, the attribute name used to access the user's name
 * from the UserInfo response is required and therefore must be available via
 * {@link org.springframework.security.oauth2.client.registration.ClientRegistration.ProviderDetails.UserInfoEndpoint#getUserNameAttributeName() UserInfoEndpoint.getUserNameAttributeName()}.
 * <p>
 * <b>NOTE:</b> Attribute names are <b>not</b> standardized between providers and therefore will vary.
 * Please consult the provider's API documentation for the set of supported user attribute names.
 *
 * @author Rob Winch
 * @since 5.1
 * @see ReactiveOAuth2UserService
 * @see OAuth2UserRequest
 * @see OAuth2User
 * @see DefaultOAuth2User
 */
public class DefaultReactiveOAuth2UserService implements ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> {
	private static final String INVALID_USER_INFO_RESPONSE_ERROR_CODE = "invalid_user_info_response";
	private static final String MISSING_USER_INFO_URI_ERROR_CODE = "missing_user_info_uri";
	private static final String MISSING_USER_NAME_ATTRIBUTE_ERROR_CODE = "missing_user_name_attribute";

	private WebClient webClient = WebClient.create();

	@Override
	public Mono<OAuth2User> loadUser(OAuth2UserRequest userRequest)
			throws OAuth2AuthenticationException {
		return Mono.defer(() -> {
			Assert.notNull(userRequest, "userRequest cannot be null");

			String userInfoUri = userRequest.getClientRegistration().getProviderDetails()
					.getUserInfoEndpoint().getUri();
			if (!StringUtils.hasText(
					userInfoUri)) {
				OAuth2Error oauth2Error = new OAuth2Error(
						MISSING_USER_INFO_URI_ERROR_CODE,
						"Missing required UserInfo Uri in UserInfoEndpoint for Client Registration: "
								+ userRequest.getClientRegistration().getRegistrationId(),
						null);
				throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
			}
			String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint()
					.getUserNameAttributeName();
			if (!StringUtils.hasText(userNameAttributeName)) {
				OAuth2Error oauth2Error = new OAuth2Error(
						MISSING_USER_NAME_ATTRIBUTE_ERROR_CODE,
						"Missing required \"user name\" attribute name in UserInfoEndpoint for Client Registration: "
								+ userRequest.getClientRegistration().getRegistrationId(),
						null);
				throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
			}

			ParameterizedTypeReference<Map<String, Object>> typeReference = new ParameterizedTypeReference<Map<String, Object>>() {
			};

			AuthenticationMethod authenticationMethod = userRequest.getClientRegistration().getProviderDetails()
					.getUserInfoEndpoint().getAuthenticationMethod();
			WebClient.RequestHeadersSpec<?> requestHeadersSpec;
			if (AuthenticationMethod.FORM.equals(authenticationMethod)) {
				requestHeadersSpec = this.webClient.post()
						.uri(userInfoUri)
						.header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
						.header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
						.syncBody("access_token=" + userRequest.getAccessToken().getTokenValue());
			} else {
				requestHeadersSpec = this.webClient.get()
						.uri(userInfoUri)
						.header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
						.headers(headers -> headers.setBearerAuth(userRequest.getAccessToken().getTokenValue()));
			}
			Mono<Map<String, Object>> userAttributes = requestHeadersSpec
					.retrieve()
					.onStatus(s -> s != HttpStatus.OK, response -> parse(response).map(userInfoErrorResponse -> {
						String description = userInfoErrorResponse.getErrorObject().getDescription();
						OAuth2Error oauth2Error = new OAuth2Error(
								INVALID_USER_INFO_RESPONSE_ERROR_CODE, description,
								null);
						throw new OAuth2AuthenticationException(oauth2Error,
								oauth2Error.toString());
					}))
					.bodyToMono(typeReference);

			return userAttributes.map(attrs -> {
				GrantedAuthority authority = new OAuth2UserAuthority(attrs);
				Set<GrantedAuthority> authorities = new HashSet<>();
				authorities.add(authority);
				OAuth2AccessToken token = userRequest.getAccessToken();
				for (String scope : token.getScopes()) {
					authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope));
				}

				return new DefaultOAuth2User(authorities, attrs, userNameAttributeName);
			})
			.onErrorMap(IOException.class, e -> new AuthenticationServiceException("Unable to access the userInfoEndpoint " + userInfoUri, e))
			.onErrorMap(UnsupportedMediaTypeException.class, e -> {
				String errorMessage = "An error occurred while attempting to retrieve the UserInfo Resource from '" +
						userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUri() +
						"': response contains invalid content type '" + e.getContentType().toString() + "'. " +
						"The UserInfo Response should return a JSON object (content type 'application/json') " +
						"that contains a collection of name and value pairs of the claims about the authenticated End-User. " +
						"Please ensure the UserInfo Uri in UserInfoEndpoint for Client Registration '" +
						userRequest.getClientRegistration().getRegistrationId() + "' conforms to the UserInfo Endpoint, " +
						"as defined in OpenID Connect 1.0: 'https://openid.net/specs/openid-connect-core-1_0.html#UserInfo'";
				OAuth2Error oauth2Error = new OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE, errorMessage, null);
				throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString(), e);
			})
			.onErrorMap(t -> !(t instanceof AuthenticationServiceException), t -> {
				OAuth2Error oauth2Error = new OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE,  "An error occurred reading the UserInfo Success response: " + t.getMessage(), null);
				return new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString(), t);
			});
		});
	}

	/**
	 * Sets the {@link WebClient} used for retrieving the user endpoint
	 * @param webClient the client to use
	 */
	public void setWebClient(WebClient webClient) {
		Assert.notNull(webClient, "webClient cannot be null");
		this.webClient = webClient;
	}

	private static Mono<UserInfoErrorResponse> parse(ClientResponse httpResponse) {

		String wwwAuth = httpResponse.headers().asHttpHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE);

		if (!StringUtils.isEmpty(wwwAuth)) {
			// Bearer token error?
			return Mono.fromCallable(() -> UserInfoErrorResponse.parse(wwwAuth));
		}

		ParameterizedTypeReference<Map<String, String>> typeReference =
				new ParameterizedTypeReference<Map<String, String>>() {};
		// Other error?
		return httpResponse
			.bodyToMono(typeReference)
			.map(body -> new UserInfoErrorResponse(ErrorObject.parse(new JSONObject(body))));
	}
}
