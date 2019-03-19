package org.springframework.security.test.context.support.oauth2.annotations;

import static org.springframework.util.StringUtils.isEmpty;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.test.context.support.oauth2.support.OidcIdSupport;

public @interface MockOAuth2AuthorizationRequest {

	String authorizationGrantType() default OidcIdSupport.REQUEST_GRANT_TYPE;

	String authorizationUri() default OidcIdSupport.REQUEST_AUTHORIZATION_URI;

	String clientId() default OidcIdSupport.CLIENT_ID;

	String redirectUri() default OidcIdSupport.REQUEST_REDIRECT_URI;

	String state() default "";

	Attribute[] additionalParameters() default {};

	String authorizationRequestUri() default "";

	Attribute[] attributes() default {};

	String responseType() default "";

	public static class MockOAuth2AuthorizationRequestSupport {

		public static OAuth2AuthorizationRequest.Builder authorizationRequestBuilder(
				final MockOAuth2AuthorizationRequest annotation,
				final AttributeParsersSupport propertyParsersHelper) {
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
