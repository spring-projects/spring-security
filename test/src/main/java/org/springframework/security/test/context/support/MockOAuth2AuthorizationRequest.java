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
package org.springframework.security.test.context.support;

import static org.springframework.util.StringUtils.isEmpty;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.test.support.OidcIdTokenAuthenticationBuilder;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 * @since 5.2
 */
public @interface MockOAuth2AuthorizationRequest {

	String authorizationGrantType() default OidcIdTokenAuthenticationBuilder.DEFAULT_REQUEST_GRANT_TYPE;

	String authorizationUri() default OidcIdTokenAuthenticationBuilder.DEFAULT_REQUEST_AUTHORIZATION_URI;

	String clientId() default OidcIdTokenAuthenticationBuilder.DEFAULT_CLIENT_ID;

	String redirectUri() default OidcIdTokenAuthenticationBuilder.DEFAULT_REQUEST_REDIRECT_URI;

	String state() default "";

	StringAttribute[] additionalParameters() default {};

	String authorizationRequestUri() default "";

	StringAttribute[] stringAttributes() default {};

	String responseType() default "";

	public static class MockOAuth2AuthorizationRequestSupport {

		public static OAuth2AuthorizationRequest.Builder authorizationRequestBuilder(
				final MockOAuth2AuthorizationRequest annotation,
				final StringAttributeParserSupport propertyParsersHelper) {
			OAuth2AuthorizationRequest.Builder builder;
			if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(annotation.authorizationGrantType())) {
				builder = OAuth2AuthorizationRequest.authorizationCode();
			} else if (AuthorizationGrantType.IMPLICIT.getValue().equals(annotation.authorizationGrantType())) {
				builder = OAuth2AuthorizationRequest.implicit();
			} else {
				throw new UnsupportedOperationException(
						"Only authorization_code and implicit grant types are supported for MockOAuth2AuthorizationRequest");
			}
			builder.additionalParameters(propertyParsersHelper.parse(annotation.additionalParameters()));
			builder.authorizationRequestUri(
					isEmpty(annotation.authorizationRequestUri()) ? null : annotation.authorizationRequestUri());
			builder.authorizationUri(isEmpty(annotation.authorizationUri()) ? null : annotation.authorizationUri());
			builder.clientId(isEmpty(annotation.clientId()) ? null : annotation.clientId());
			builder.redirectUri(isEmpty(annotation.redirectUri()) ? null : annotation.redirectUri());
			return builder;
		}
	}

}
