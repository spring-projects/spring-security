package org.springframework.security.test.context.support.oauth2.annotations;

import static org.springframework.util.StringUtils.isEmpty;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Target;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.test.context.support.oauth2.support.OidcIdSupport;

@Inherited
@Documented
@Target(ElementType.ANNOTATION_TYPE)
public @interface MockClientRegistration {

	String authorizationGrantType() default OidcIdSupport.CLIENT_GRANT_TYPE;

	String clientId() default OidcIdSupport.CLIENT_ID;

	String registrationId() default OidcIdSupport.CLIENT_REGISTRATION_ID;

	String tokenUri() default OidcIdSupport.CLIENT_TOKEN_URI;

	String authorizationUri() default "";

	String clientAuthenticationMethod() default "basic";

	String clientName() default "";

	String clientSecret() default "";

	String jwkSetUri() default "";

	Attribute[] providerConfigurationMetadata() default {};

	String redirectUriTemplate() default "";

	String userInfoAuthenticationMethod() default "header";

	String userInfoUri() default "";

	String userNameAttributeName() default "";

	public static class MockClientRegistrationSupport {

		public static ClientRegistration.Builder clientRegistrationBuilder(
				final MockClientRegistration annotation,
				final AttributeParsersSupport propertyParsersHelper) {
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
