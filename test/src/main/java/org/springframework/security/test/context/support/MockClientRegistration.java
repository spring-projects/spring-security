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

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Target;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.test.support.OidcIdTokenAuthenticationBuilder;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 * @since 5.2
 */
@Inherited
@Documented
@Target(ElementType.ANNOTATION_TYPE)
public @interface MockClientRegistration {

	String authorizationGrantType() default OidcIdTokenAuthenticationBuilder.DEFAULT_CLIENT_GRANT_TYPE;

	String clientId() default OidcIdTokenAuthenticationBuilder.DEFAULT_CLIENT_ID;

	String registrationId() default OidcIdTokenAuthenticationBuilder.DEFAULT_CLIENT_REGISTRATION_ID;

	String tokenUri() default OidcIdTokenAuthenticationBuilder.DEFAULT_CLIENT_TOKEN_URI;

	String authorizationUri() default "";

	String clientAuthenticationMethod() default "basic";

	String clientName() default "";

	String clientSecret() default "";

	String jwkSetUri() default "";

	StringAttribute[] providerConfigurationMetadata() default {};

	String redirectUriTemplate() default "";

	String userInfoAuthenticationMethod() default "header";

	String userInfoUri() default "";

	String userNameAttributeName() default "";

	public static class MockClientRegistrationSupport {

		public static ClientRegistration.Builder clientRegistrationBuilder(
				final MockClientRegistration annotation,
				final StringAttributeParserSupport propertyParsersHelper) {
			return ClientRegistration.withRegistrationId(annotation.registrationId())
					.authorizationGrantType(
							isEmpty(annotation.authorizationGrantType()) ? null
									: new AuthorizationGrantType(annotation.authorizationGrantType()))
					.authorizationUri(isEmpty(annotation.authorizationUri()) ? null : annotation.authorizationUri())
					.clientAuthenticationMethod(
							isEmpty(annotation.clientAuthenticationMethod()) ? null
									: new ClientAuthenticationMethod(annotation.clientAuthenticationMethod()))
					.clientId(isEmpty(annotation.clientId()) ? null : annotation.clientId())
					.clientName(isEmpty(annotation.clientName()) ? null : annotation.clientName())
					.clientSecret(isEmpty(annotation.clientSecret()) ? null : annotation.clientSecret())
					.jwkSetUri(isEmpty(annotation.jwkSetUri()) ? null : annotation.jwkSetUri())
					.providerConfigurationMetadata(
							propertyParsersHelper.parse(annotation.providerConfigurationMetadata()))
					.redirectUriTemplate(
							isEmpty(annotation.redirectUriTemplate()) ? null : annotation.redirectUriTemplate())
					.registrationId(isEmpty(annotation.registrationId()) ? null : annotation.registrationId())
					.tokenUri(isEmpty(annotation.tokenUri()) ? null : annotation.tokenUri())
					.userInfoAuthenticationMethod(
							isEmpty(annotation.userInfoAuthenticationMethod()) ? null
									: new AuthenticationMethod(annotation.userInfoAuthenticationMethod()));
		}

	}
}
