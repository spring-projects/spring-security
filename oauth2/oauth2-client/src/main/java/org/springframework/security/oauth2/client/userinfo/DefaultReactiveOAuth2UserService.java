/*
 * Copyright 2002-2024 the original author or authors.
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

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import net.minidev.json.JSONObject;
import reactor.core.publisher.Mono;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
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

/**
 * An implementation of an {@link ReactiveOAuth2UserService} that supports standard OAuth
 * 2.0 Provider's.
 * <p>
 * For standard OAuth 2.0 Provider's, the attribute name used to access the user's name
 * from the UserInfo response is required and therefore must be available via
 * {@link org.springframework.security.oauth2.client.registration.ClientRegistration.ProviderDetails.UserInfoEndpoint#getUserNameAttributeName()
 * UserInfoEndpoint.getUserNameAttributeName()}.
 * <p>
 * <b>NOTE:</b> Attribute names are <b>not</b> standardized between providers and
 * therefore will vary. Please consult the provider's API documentation for the set of
 * supported user attribute names.
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

	private static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP = new ParameterizedTypeReference<>() {
	};

	private static final ParameterizedTypeReference<Map<String, String>> STRING_STRING_MAP = new ParameterizedTypeReference<>() {
	};

	private Converter<OAuth2UserRequest, Converter<Map<String, Object>, Map<String, Object>>> attributesConverter = (
			request) -> (attributes) -> attributes;

	private WebClient webClient = WebClient.create();

	@Override
	public Mono<OAuth2User> loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		return Mono.defer(() -> {
			Assert.notNull(userRequest, "userRequest cannot be null");
			String userInfoUri = userRequest.getClientRegistration()
				.getProviderDetails()
				.getUserInfoEndpoint()
				.getUri();
			if (!StringUtils.hasText(userInfoUri)) {
				OAuth2Error oauth2Error = new OAuth2Error(MISSING_USER_INFO_URI_ERROR_CODE,
						"Missing required UserInfo Uri in UserInfoEndpoint for Client Registration: "
								+ userRequest.getClientRegistration().getRegistrationId(),
						null);
				throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
			}
			String userNameAttributeName = userRequest.getClientRegistration()
				.getProviderDetails()
				.getUserInfoEndpoint()
				.getUserNameAttributeName();
			if (!StringUtils.hasText(userNameAttributeName)) {
				OAuth2Error oauth2Error = new OAuth2Error(MISSING_USER_NAME_ATTRIBUTE_ERROR_CODE,
						"Missing required \"user name\" attribute name in UserInfoEndpoint for Client Registration: "
								+ userRequest.getClientRegistration().getRegistrationId(),
						null);
				throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
			}
			AuthenticationMethod authenticationMethod = userRequest.getClientRegistration()
				.getProviderDetails()
				.getUserInfoEndpoint()
				.getAuthenticationMethod();
			WebClient.RequestHeadersSpec<?> requestHeadersSpec = getRequestHeaderSpec(userRequest, userInfoUri,
					authenticationMethod);
			// @formatter:off
			Mono<Map<String, Object>> userAttributes = requestHeadersSpec.retrieve()
					.onStatus(HttpStatusCode::isError, (response) ->
						parse(response)
							.map((userInfoErrorResponse) -> {
								String description = userInfoErrorResponse.getErrorObject().getDescription();
								OAuth2Error oauth2Error = new OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE, description,
									null);
								throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
							})
					)
					.bodyToMono(DefaultReactiveOAuth2UserService.STRING_OBJECT_MAP)
					.mapNotNull((attributes) -> this.attributesConverter.convert(userRequest).convert(attributes));
			return userAttributes.map((attrs) -> {
				GrantedAuthority authority = new OAuth2UserAuthority(attrs, userNameAttributeName);
				Set<GrantedAuthority> authorities = new HashSet<>();
				authorities.add(authority);
				OAuth2AccessToken token = userRequest.getAccessToken();
				for (String scope : token.getScopes()) {
					authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope));
				}

				return new DefaultOAuth2User(authorities, attrs, userNameAttributeName);
			})
			.onErrorMap((ex) -> (ex instanceof UnsupportedMediaTypeException ||
					ex.getCause() instanceof UnsupportedMediaTypeException), (ex) -> {
				String contentType = (ex instanceof UnsupportedMediaTypeException) ?
						((UnsupportedMediaTypeException) ex).getContentType().toString() :
						((UnsupportedMediaTypeException) ex.getCause()).getContentType().toString();
				String errorMessage = "An error occurred while attempting to retrieve the UserInfo Resource from '"
						+ userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint()
								.getUri()
						+ "': response contains invalid content type '" + contentType + "'. "
						+ "The UserInfo Response should return a JSON object (content type 'application/json') "
						+ "that contains a collection of name and value pairs of the claims about the authenticated End-User. "
						+ "Please ensure the UserInfo Uri in UserInfoEndpoint for Client Registration '"
						+ userRequest.getClientRegistration().getRegistrationId()
						+ "' conforms to the UserInfo Endpoint, "
						+ "as defined in OpenID Connect 1.0: 'https://openid.net/specs/openid-connect-core-1_0.html#UserInfo'";
				OAuth2Error oauth2Error = new OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE, errorMessage,
						null);
				throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString(), ex);
			})
			.onErrorMap((ex) -> {
				OAuth2Error oauth2Error = new OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE,
						"An error occurred reading the UserInfo response: " + ex.getMessage(), null);
				return new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString(), ex);
			});
		});
		// @formatter:on
	}

	private WebClient.RequestHeadersSpec<?> getRequestHeaderSpec(OAuth2UserRequest userRequest, String userInfoUri,
			AuthenticationMethod authenticationMethod) {
		if (AuthenticationMethod.FORM.equals(authenticationMethod)) {
			// @formatter:off
			return this.webClient.post()
					.uri(userInfoUri)
					.header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
					.header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
					.bodyValue("access_token=" + userRequest.getAccessToken().getTokenValue());
			// @formatter:on
		}
		// @formatter:off
		return this.webClient.get()
				.uri(userInfoUri)
				.header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
				.headers((headers) -> headers
						.setBearerAuth(userRequest.getAccessToken().getTokenValue())
				);
		// @formatter:on
	}

	/**
	 * Use this strategy to adapt user attributes into a format understood by Spring
	 * Security; by default, the original attributes are preserved.
	 *
	 * <p>
	 * This can be helpful, for example, if the user attribute is nested. Since Spring
	 * Security needs the username attribute to be at the top level, you can use this
	 * method to do:
	 *
	 * <pre>
	 *     DefaultReactiveOAuth2UserService userService = new DefaultReactiveOAuth2UserService();
	 *     userService.setAttributesConverter((userRequest) -> (attributes) ->
	 *         Map&lt;String, Object&gt; userObject = (Map&lt;String, Object&gt;) attributes.get("user");
	 *         attributes.put("user-name", userObject.get("user-name"));
	 *         return attributes;
	 *     });
	 * </pre>
	 * @param attributesConverter the attribute adaptation strategy to use
	 * @since 6.3
	 */
	public void setAttributesConverter(
			Converter<OAuth2UserRequest, Converter<Map<String, Object>, Map<String, Object>>> attributesConverter) {
		Assert.notNull(attributesConverter, "attributesConverter cannot be null");
		this.attributesConverter = attributesConverter;
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
		if (StringUtils.hasLength(wwwAuth)) {
			// Bearer token error?
			return Mono.fromCallable(() -> UserInfoErrorResponse.parse(wwwAuth));
		}
		// Other error?
		return httpResponse.bodyToMono(STRING_STRING_MAP)
			.map((body) -> new UserInfoErrorResponse(ErrorObject.parse(new JSONObject(body))));
	}

}
