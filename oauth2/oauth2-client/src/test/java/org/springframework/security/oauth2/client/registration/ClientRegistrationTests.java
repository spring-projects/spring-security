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
package org.springframework.security.oauth2.client.registration;

import org.junit.Test;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link ClientRegistration}.
 *
 * @author Joe Grandja
 */
public class ClientRegistrationTests {
	private static final String REGISTRATION_ID = "registration-1";
	private static final String CLIENT_ID = "client-1";
	private static final String CLIENT_SECRET = "secret";
	private static final String REDIRECT_URI = "https://example.com";
	private static final Set<String> SCOPES = Collections.unmodifiableSet(
			Stream.of("openid", "profile", "email").collect(Collectors.toSet()));
	private static final String AUTHORIZATION_URI = "https://provider.com/oauth2/authorization";
	private static final String TOKEN_URI = "https://provider.com/oauth2/token";
	private static final String JWK_SET_URI = "https://provider.com/oauth2/keys";
	private static final String CLIENT_NAME = "Client 1";
	private static final Map<String, Object> PROVIDER_CONFIGURATION_METADATA =
			Collections.unmodifiableMap(createProviderConfigurationMetadata());

	private static Map<String, Object> createProviderConfigurationMetadata() {
		Map<String, Object> configurationMetadata = new LinkedHashMap<>();
		configurationMetadata.put("config-1", "value-1");
		configurationMetadata.put("config-2", "value-2");
		return configurationMetadata;
	}

	@Test(expected = IllegalArgumentException.class)
	public void buildWhenAuthorizationGrantTypeIsNullThenThrowIllegalArgumentException() {
		ClientRegistration.withRegistrationId(REGISTRATION_ID)
			.clientId(CLIENT_ID)
			.clientSecret(CLIENT_SECRET)
			.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
			.authorizationGrantType(null)
			.redirectUriTemplate(REDIRECT_URI)
			.scope(SCOPES.toArray(new String[0]))
			.authorizationUri(AUTHORIZATION_URI)
			.tokenUri(TOKEN_URI)
			.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
			.jwkSetUri(JWK_SET_URI)
			.clientName(CLIENT_NAME)
			.build();
	}

	@Test
	public void buildWhenAuthorizationCodeGrantAllAttributesProvidedThenAllAttributesAreSet() {
		ClientRegistration registration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
			.clientId(CLIENT_ID)
			.clientSecret(CLIENT_SECRET)
			.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUriTemplate(REDIRECT_URI)
			.scope(SCOPES.toArray(new String[0]))
			.authorizationUri(AUTHORIZATION_URI)
			.tokenUri(TOKEN_URI)
			.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
			.jwkSetUri(JWK_SET_URI)
			.providerConfigurationMetadata(PROVIDER_CONFIGURATION_METADATA)
			.clientName(CLIENT_NAME)
			.build();

		assertThat(registration.getRegistrationId()).isEqualTo(REGISTRATION_ID);
		assertThat(registration.getClientId()).isEqualTo(CLIENT_ID);
		assertThat(registration.getClientSecret()).isEqualTo(CLIENT_SECRET);
		assertThat(registration.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.BASIC);
		assertThat(registration.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(registration.getRedirectUriTemplate()).isEqualTo(REDIRECT_URI);
		assertThat(registration.getScopes()).isEqualTo(SCOPES);
		assertThat(registration.getProviderDetails().getAuthorizationUri()).isEqualTo(AUTHORIZATION_URI);
		assertThat(registration.getProviderDetails().getTokenUri()).isEqualTo(TOKEN_URI);
		assertThat(registration.getProviderDetails().getUserInfoEndpoint().getAuthenticationMethod()).isEqualTo(AuthenticationMethod.FORM);
		assertThat(registration.getProviderDetails().getJwkSetUri()).isEqualTo(JWK_SET_URI);
		assertThat(registration.getProviderDetails().getConfigurationMetadata()).isEqualTo(PROVIDER_CONFIGURATION_METADATA);
		assertThat(registration.getClientName()).isEqualTo(CLIENT_NAME);
	}

	@Test(expected = IllegalArgumentException.class)
	public void buildWhenAuthorizationCodeGrantRegistrationIdIsNullThenThrowIllegalArgumentException() {
		ClientRegistration.withRegistrationId(null)
			.clientId(CLIENT_ID)
			.clientSecret(CLIENT_SECRET)
			.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUriTemplate(REDIRECT_URI)
			.scope(SCOPES.toArray(new String[0]))
			.authorizationUri(AUTHORIZATION_URI)
			.tokenUri(TOKEN_URI)
			.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
			.jwkSetUri(JWK_SET_URI)
			.clientName(CLIENT_NAME)
			.build();
	}

	@Test(expected = IllegalArgumentException.class)
	public void buildWhenAuthorizationCodeGrantClientIdIsNullThenThrowIllegalArgumentException() {
		ClientRegistration.withRegistrationId(REGISTRATION_ID)
			.clientId(null)
			.clientSecret(CLIENT_SECRET)
			.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUriTemplate(REDIRECT_URI)
			.scope(SCOPES.toArray(new String[0]))
			.authorizationUri(AUTHORIZATION_URI)
			.tokenUri(TOKEN_URI)
			.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
			.jwkSetUri(JWK_SET_URI)
			.clientName(CLIENT_NAME)
			.build();
	}

	@Test
	public void buildWhenAuthorizationCodeGrantClientSecretIsNullThenDefaultToEmpty() {
		ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.clientSecret(null)
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUriTemplate(REDIRECT_URI)
				.scope(SCOPES.toArray(new String[0]))
				.authorizationUri(AUTHORIZATION_URI)
				.tokenUri(TOKEN_URI)
				.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
				.jwkSetUri(JWK_SET_URI)
				.clientName(CLIENT_NAME)
				.build();
		assertThat(clientRegistration.getClientSecret()).isEqualTo("");
	}

	@Test
	public void buildWhenAuthorizationCodeGrantClientAuthenticationMethodNotProvidedThenDefaultToBasic() {
		ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUriTemplate(REDIRECT_URI)
				.scope(SCOPES.toArray(new String[0]))
				.authorizationUri(AUTHORIZATION_URI)
				.tokenUri(TOKEN_URI)
				.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
				.jwkSetUri(JWK_SET_URI)
				.clientName(CLIENT_NAME)
				.build();
		assertThat(clientRegistration.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.BASIC);
	}

	@Test
	public void buildWhenAuthorizationCodeGrantClientAuthenticationMethodNotProvidedAndClientSecretNullThenDefaultToNone() {
		ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.clientSecret(null)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUriTemplate(REDIRECT_URI)
				.scope(SCOPES.toArray(new String[0]))
				.authorizationUri(AUTHORIZATION_URI)
				.tokenUri(TOKEN_URI)
				.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
				.jwkSetUri(JWK_SET_URI)
				.clientName(CLIENT_NAME)
				.build();
		assertThat(clientRegistration.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.NONE);
	}

	@Test
	public void buildWhenAuthorizationCodeGrantClientAuthenticationMethodNotProvidedAndClientSecretBlankThenDefaultToNone() {
		ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.clientSecret(" ")
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUriTemplate(REDIRECT_URI)
				.scope(SCOPES.toArray(new String[0]))
				.authorizationUri(AUTHORIZATION_URI)
				.tokenUri(TOKEN_URI)
				.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
				.jwkSetUri(JWK_SET_URI)
				.clientName(CLIENT_NAME)
				.build();
		assertThat(clientRegistration.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.NONE);
		assertThat(clientRegistration.getClientSecret()).isEqualTo("");
	}

	@Test(expected = IllegalArgumentException.class)
	public void buildWhenAuthorizationCodeGrantRedirectUriIsNullThenThrowIllegalArgumentException() {
		ClientRegistration.withRegistrationId(REGISTRATION_ID)
			.clientId(CLIENT_ID)
			.clientSecret(CLIENT_SECRET)
			.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUriTemplate(null)
			.scope(SCOPES.toArray(new String[0]))
			.authorizationUri(AUTHORIZATION_URI)
			.tokenUri(TOKEN_URI)
			.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
			.jwkSetUri(JWK_SET_URI)
			.clientName(CLIENT_NAME)
			.build();
	}

	// gh-5494
	@Test
	public void buildWhenAuthorizationCodeGrantScopeIsNullThenScopeNotRequired() {
		ClientRegistration.withRegistrationId(REGISTRATION_ID)
			.clientId(CLIENT_ID)
			.clientSecret(CLIENT_SECRET)
			.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUriTemplate(REDIRECT_URI)
			.scope((String[]) null)
			.authorizationUri(AUTHORIZATION_URI)
			.tokenUri(TOKEN_URI)
			.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
			.jwkSetUri(JWK_SET_URI)
			.clientName(CLIENT_NAME)
			.build();
	}

	@Test(expected = IllegalArgumentException.class)
	public void buildWhenAuthorizationCodeGrantAuthorizationUriIsNullThenThrowIllegalArgumentException() {
		ClientRegistration.withRegistrationId(REGISTRATION_ID)
			.clientId(CLIENT_ID)
			.clientSecret(CLIENT_SECRET)
			.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUriTemplate(REDIRECT_URI)
			.scope(SCOPES.toArray(new String[0]))
			.authorizationUri(null)
			.tokenUri(TOKEN_URI)
			.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
			.jwkSetUri(JWK_SET_URI)
			.clientName(CLIENT_NAME)
			.build();
	}

	@Test(expected = IllegalArgumentException.class)
	public void buildWhenAuthorizationCodeGrantTokenUriIsNullThenThrowIllegalArgumentException() {
		ClientRegistration.withRegistrationId(REGISTRATION_ID)
			.clientId(CLIENT_ID)
			.clientSecret(CLIENT_SECRET)
			.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUriTemplate(REDIRECT_URI)
			.scope(SCOPES.toArray(new String[0]))
			.authorizationUri(AUTHORIZATION_URI)
			.tokenUri(null)
			.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
			.jwkSetUri(JWK_SET_URI)
			.clientName(CLIENT_NAME)
			.build();
	}

	@Test
	public void buildWhenAuthorizationCodeGrantClientNameNotProvidedThenDefaultToRegistrationId() {
		ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUriTemplate(REDIRECT_URI)
				.scope(SCOPES.toArray(new String[0]))
				.authorizationUri(AUTHORIZATION_URI)
				.tokenUri(TOKEN_URI)
				.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
				.jwkSetUri(JWK_SET_URI)
				.build();
		assertThat(clientRegistration.getClientName()).isEqualTo(clientRegistration.getRegistrationId());
	}

	@Test
	public void buildWhenAuthorizationCodeGrantScopeDoesNotContainOpenidThenJwkSetUriNotRequired() {
		ClientRegistration.withRegistrationId(REGISTRATION_ID)
			.clientId(CLIENT_ID)
			.clientSecret(CLIENT_SECRET)
			.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUriTemplate(REDIRECT_URI)
			.scope("scope1")
			.authorizationUri(AUTHORIZATION_URI)
			.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
			.tokenUri(TOKEN_URI)
			.clientName(CLIENT_NAME)
			.build();
	}

	// gh-5494
	@Test
	public void buildWhenAuthorizationCodeGrantScopeIsNullThenJwkSetUriNotRequired() {
		ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUriTemplate(REDIRECT_URI)
				.authorizationUri(AUTHORIZATION_URI)
				.tokenUri(TOKEN_URI)
				.clientName(CLIENT_NAME)
				.build();
	}

	@Test
	public void buildWhenAuthorizationCodeGrantProviderConfigurationMetadataIsNullThenDefaultToEmpty() {
		ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUriTemplate(REDIRECT_URI)
				.scope(SCOPES.toArray(new String[0]))
				.authorizationUri(AUTHORIZATION_URI)
				.tokenUri(TOKEN_URI)
				.userInfoAuthenticationMethod(AuthenticationMethod.HEADER)
				.providerConfigurationMetadata(null)
				.jwkSetUri(JWK_SET_URI)
				.clientName(CLIENT_NAME)
				.build();
		assertThat(clientRegistration.getProviderDetails().getConfigurationMetadata()).isNotNull();
		assertThat(clientRegistration.getProviderDetails().getConfigurationMetadata()).isEmpty();
	}

	@Test
	public void buildWhenAuthorizationCodeGrantProviderConfigurationMetadataEmptyThenIsEmpty() {
		ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUriTemplate(REDIRECT_URI)
				.scope(SCOPES.toArray(new String[0]))
				.authorizationUri(AUTHORIZATION_URI)
				.tokenUri(TOKEN_URI)
				.userInfoAuthenticationMethod(AuthenticationMethod.HEADER)
				.providerConfigurationMetadata(Collections.emptyMap())
				.jwkSetUri(JWK_SET_URI)
				.clientName(CLIENT_NAME)
				.build();
		assertThat(clientRegistration.getProviderDetails().getConfigurationMetadata()).isNotNull();
		assertThat(clientRegistration.getProviderDetails().getConfigurationMetadata()).isEmpty();
	}

	@Test
	public void buildWhenImplicitGrantAllAttributesProvidedThenAllAttributesAreSet() {
		ClientRegistration registration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
			.clientId(CLIENT_ID)
			.authorizationGrantType(AuthorizationGrantType.IMPLICIT)
			.redirectUriTemplate(REDIRECT_URI)
			.scope(SCOPES.toArray(new String[0]))
			.authorizationUri(AUTHORIZATION_URI)
			.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
			.clientName(CLIENT_NAME)
			.build();

		assertThat(registration.getRegistrationId()).isEqualTo(REGISTRATION_ID);
		assertThat(registration.getClientId()).isEqualTo(CLIENT_ID);
		assertThat(registration.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.IMPLICIT);
		assertThat(registration.getRedirectUriTemplate()).isEqualTo(REDIRECT_URI);
		assertThat(registration.getScopes()).isEqualTo(SCOPES);
		assertThat(registration.getProviderDetails().getAuthorizationUri()).isEqualTo(AUTHORIZATION_URI);
		assertThat(registration.getProviderDetails().getUserInfoEndpoint().getAuthenticationMethod()).isEqualTo(AuthenticationMethod.FORM);
		assertThat(registration.getClientName()).isEqualTo(CLIENT_NAME);
	}

	@Test(expected = IllegalArgumentException.class)
	public void buildWhenImplicitGrantRegistrationIdIsNullThenThrowIllegalArgumentException() {
		ClientRegistration.withRegistrationId(null)
			.clientId(CLIENT_ID)
			.authorizationGrantType(AuthorizationGrantType.IMPLICIT)
			.redirectUriTemplate(REDIRECT_URI)
			.scope(SCOPES.toArray(new String[0]))
			.authorizationUri(AUTHORIZATION_URI)
			.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
			.clientName(CLIENT_NAME)
			.build();
	}

	@Test(expected = IllegalArgumentException.class)
	public void buildWhenImplicitGrantClientIdIsNullThenThrowIllegalArgumentException() {
		ClientRegistration.withRegistrationId(REGISTRATION_ID)
			.clientId(null)
			.authorizationGrantType(AuthorizationGrantType.IMPLICIT)
			.redirectUriTemplate(REDIRECT_URI)
			.scope(SCOPES.toArray(new String[0]))
			.authorizationUri(AUTHORIZATION_URI)
			.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
			.clientName(CLIENT_NAME)
			.build();
	}

	@Test(expected = IllegalArgumentException.class)
	public void buildWhenImplicitGrantRedirectUriIsNullThenThrowIllegalArgumentException() {
		ClientRegistration.withRegistrationId(REGISTRATION_ID)
			.clientId(CLIENT_ID)
			.authorizationGrantType(AuthorizationGrantType.IMPLICIT)
			.redirectUriTemplate(null)
			.scope(SCOPES.toArray(new String[0]))
			.authorizationUri(AUTHORIZATION_URI)
			.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
			.clientName(CLIENT_NAME)
			.build();
	}

	// gh-5494
	@Test
	public void buildWhenImplicitGrantScopeIsNullThenScopeNotRequired() {
		ClientRegistration.withRegistrationId(REGISTRATION_ID)
			.clientId(CLIENT_ID)
			.authorizationGrantType(AuthorizationGrantType.IMPLICIT)
			.redirectUriTemplate(REDIRECT_URI)
			.scope((String[]) null)
			.authorizationUri(AUTHORIZATION_URI)
			.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
			.clientName(CLIENT_NAME)
			.build();
	}

	@Test(expected = IllegalArgumentException.class)
	public void buildWhenImplicitGrantAuthorizationUriIsNullThenThrowIllegalArgumentException() {
		ClientRegistration.withRegistrationId(REGISTRATION_ID)
			.clientId(CLIENT_ID)
			.authorizationGrantType(AuthorizationGrantType.IMPLICIT)
			.redirectUriTemplate(REDIRECT_URI)
			.scope(SCOPES.toArray(new String[0]))
			.authorizationUri(null)
			.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
			.clientName(CLIENT_NAME)
			.build();
	}

	@Test
	public void buildWhenImplicitGrantClientNameNotProvidedThenDefaultToRegistrationId() {
		ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.authorizationGrantType(AuthorizationGrantType.IMPLICIT)
				.redirectUriTemplate(REDIRECT_URI)
				.scope(SCOPES.toArray(new String[0]))
				.authorizationUri(AUTHORIZATION_URI)
				.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
				.build();
		assertThat(clientRegistration.getClientName()).isEqualTo(clientRegistration.getRegistrationId());
	}

	@Test
	public void buildWhenOverrideRegistrationIdThenOverridden() {
		String overriddenId = "override";
		ClientRegistration registration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.registrationId(overriddenId)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUriTemplate(REDIRECT_URI)
				.scope(SCOPES.toArray(new String[0]))
				.authorizationUri(AUTHORIZATION_URI)
				.tokenUri(TOKEN_URI)
				.jwkSetUri(JWK_SET_URI)
				.clientName(CLIENT_NAME)
				.build();

		assertThat(registration.getRegistrationId()).isEqualTo(overriddenId);
	}

	@Test
	public void buildWhenClientCredentialsGrantAllAttributesProvidedThenAllAttributesAreSet() {
		ClientRegistration registration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.scope(SCOPES.toArray(new String[0]))
				.tokenUri(TOKEN_URI)
				.clientName(CLIENT_NAME)
				.build();

		assertThat(registration.getRegistrationId()).isEqualTo(REGISTRATION_ID);
		assertThat(registration.getClientId()).isEqualTo(CLIENT_ID);
		assertThat(registration.getClientSecret()).isEqualTo(CLIENT_SECRET);
		assertThat(registration.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.BASIC);
		assertThat(registration.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.CLIENT_CREDENTIALS);
		assertThat(registration.getScopes()).isEqualTo(SCOPES);
		assertThat(registration.getProviderDetails().getTokenUri()).isEqualTo(TOKEN_URI);
		assertThat(registration.getClientName()).isEqualTo(CLIENT_NAME);
	}

	@Test
	public void buildWhenClientCredentialsGrantRegistrationIdIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() ->
				ClientRegistration.withRegistrationId(null)
						.clientId(CLIENT_ID)
						.clientSecret(CLIENT_SECRET)
						.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
						.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
						.tokenUri(TOKEN_URI)
						.build()
		).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void buildWhenClientCredentialsGrantClientIdIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() ->
				ClientRegistration.withRegistrationId(REGISTRATION_ID)
						.clientId(null)
						.clientSecret(CLIENT_SECRET)
						.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
						.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
						.tokenUri(TOKEN_URI)
						.build()
		).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void buildWhenClientCredentialsGrantClientSecretIsNullThenDefaultToEmpty() {
		ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.clientSecret(null)
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.tokenUri(TOKEN_URI)
				.build();
		assertThat(clientRegistration.getClientSecret()).isEqualTo("");
	}

	@Test
	public void buildWhenClientCredentialsGrantClientAuthenticationMethodNotProvidedThenDefaultToBasic() {
		ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.tokenUri(TOKEN_URI)
				.build();
		assertThat(clientRegistration.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.BASIC);
	}

	@Test
	public void buildWhenClientCredentialsGrantTokenUriIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() ->
				ClientRegistration.withRegistrationId(REGISTRATION_ID)
						.clientId(CLIENT_ID)
						.clientSecret(CLIENT_SECRET)
						.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
						.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
						.tokenUri(null)
						.build()
		).isInstanceOf(IllegalArgumentException.class);
	}

	// gh-6256
	@Test
	public void buildWhenScopesContainASpaceThenThrowIllegalArgumentException() {
		assertThatThrownBy(() ->
				TestClientRegistrations.clientCredentials()
						.scope("openid profile email")
						.build()
		).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void buildWhenScopesContainAnInvalidCharacterThenThrowIllegalArgumentException() {
		assertThatThrownBy(() ->
				TestClientRegistrations.clientCredentials()
						.scope("an\"invalid\"scope")
						.build()
		).isInstanceOf(IllegalArgumentException.class);
	}
}
