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

package org.springframework.security.oauth2.client.registration;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.Test;

import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

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

	private static final Set<String> SCOPES = Collections
			.unmodifiableSet(Stream.of("openid", "profile", "email").collect(Collectors.toSet()));

	private static final String AUTHORIZATION_URI = "https://provider.com/oauth2/authorization";

	private static final String TOKEN_URI = "https://provider.com/oauth2/token";

	private static final String JWK_SET_URI = "https://provider.com/oauth2/keys";

	private static final String ISSUER_URI = "https://provider.com";

	private static final String CLIENT_NAME = "Client 1";

	private static final Map<String, Object> PROVIDER_CONFIGURATION_METADATA = Collections
			.unmodifiableMap(createProviderConfigurationMetadata());

	private static Map<String, Object> createProviderConfigurationMetadata() {
		Map<String, Object> configurationMetadata = new LinkedHashMap<>();
		configurationMetadata.put("config-1", "value-1");
		configurationMetadata.put("config-2", "value-2");
		return configurationMetadata;
	}

	@Test
	public void buildWhenAuthorizationGrantTypeIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() ->
		// @formatter:off
			ClientRegistration.withRegistrationId(REGISTRATION_ID)
					.clientId(CLIENT_ID)
					.clientSecret(CLIENT_SECRET)
					.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
					.authorizationGrantType(null)
					.redirectUri(REDIRECT_URI)
					.scope(SCOPES.toArray(new String[0]))
					.authorizationUri(AUTHORIZATION_URI)
					.tokenUri(TOKEN_URI)
					.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
					.jwkSetUri(JWK_SET_URI)
					.clientName(CLIENT_NAME)
					.build()
		// @formatter:on
		);
	}

	@Test
	public void buildWhenAuthorizationCodeGrantAllAttributesProvidedThenAllAttributesAreSet() {
		// @formatter:off
		ClientRegistration registration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUri(REDIRECT_URI)
				.scope(SCOPES.toArray(new String[0]))
				.authorizationUri(AUTHORIZATION_URI)
				.tokenUri(TOKEN_URI)
				.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
				.jwkSetUri(JWK_SET_URI)
				.issuerUri(ISSUER_URI)
				.providerConfigurationMetadata(PROVIDER_CONFIGURATION_METADATA)
				.clientName(CLIENT_NAME)
				.build();
		// @formatter:on
		assertThat(registration.getRegistrationId()).isEqualTo(REGISTRATION_ID);
		assertThat(registration.getClientId()).isEqualTo(CLIENT_ID);
		assertThat(registration.getClientSecret()).isEqualTo(CLIENT_SECRET);
		assertThat(registration.getClientAuthenticationMethod())
				.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
		assertThat(registration.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(registration.getRedirectUri()).isEqualTo(REDIRECT_URI);
		assertThat(registration.getScopes()).isEqualTo(SCOPES);
		assertThat(registration.getProviderDetails().getAuthorizationUri()).isEqualTo(AUTHORIZATION_URI);
		assertThat(registration.getProviderDetails().getTokenUri()).isEqualTo(TOKEN_URI);
		assertThat(registration.getProviderDetails().getUserInfoEndpoint().getAuthenticationMethod())
				.isEqualTo(AuthenticationMethod.FORM);
		assertThat(registration.getProviderDetails().getJwkSetUri()).isEqualTo(JWK_SET_URI);
		assertThat(registration.getProviderDetails().getIssuerUri()).isEqualTo(ISSUER_URI);
		assertThat(registration.getProviderDetails().getConfigurationMetadata())
				.isEqualTo(PROVIDER_CONFIGURATION_METADATA);
		assertThat(registration.getClientName()).isEqualTo(CLIENT_NAME);
	}

	@Test
	public void buildWhenAuthorizationCodeGrantRegistrationIdIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() ->
		// @formatter:off
			ClientRegistration.withRegistrationId(null)
					.clientId(CLIENT_ID)
					.clientSecret(CLIENT_SECRET)
					.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
					.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
					.redirectUri(REDIRECT_URI)
					.scope(SCOPES.toArray(new String[0]))
					.authorizationUri(AUTHORIZATION_URI)
					.tokenUri(TOKEN_URI)
					.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
					.jwkSetUri(JWK_SET_URI)
					.clientName(CLIENT_NAME)
					.build()
		// @formatter:on
		);
	}

	@Test
	public void buildWhenAuthorizationCodeGrantClientIdIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() ->
		// @formatter:off
			ClientRegistration.withRegistrationId(REGISTRATION_ID)
					.clientId(null)
					.clientSecret(CLIENT_SECRET)
					.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
					.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
					.redirectUri(REDIRECT_URI)
					.scope(SCOPES.toArray(new String[0]))
					.authorizationUri(AUTHORIZATION_URI)
					.tokenUri(TOKEN_URI)
					.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
					.jwkSetUri(JWK_SET_URI)
					.clientName(CLIENT_NAME)
					.build()
			// @formatter:on
		);
	}

	@Test
	public void buildWhenAuthorizationCodeGrantClientSecretIsNullThenDefaultToEmpty() {
		// @formatter:off
		ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.clientSecret(null)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUri(REDIRECT_URI)
				.scope(SCOPES.toArray(new String[0]))
				.authorizationUri(AUTHORIZATION_URI)
				.tokenUri(TOKEN_URI)
				.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
				.jwkSetUri(JWK_SET_URI)
				.clientName(CLIENT_NAME)
				.build();
		// @formatter:on
		assertThat(clientRegistration.getClientSecret()).isEqualTo("");
	}

	@Test
	public void buildWhenAuthorizationCodeGrantClientAuthenticationMethodNotProvidedThenDefaultToBasic() {
		// @formatter:off
		ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUri(REDIRECT_URI)
				.scope(SCOPES.toArray(new String[0]))
				.authorizationUri(AUTHORIZATION_URI)
				.tokenUri(TOKEN_URI)
				.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
				.jwkSetUri(JWK_SET_URI)
				.clientName(CLIENT_NAME)
				.build();
		// @formatter:on
		assertThat(clientRegistration.getClientAuthenticationMethod())
				.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
	}

	@Test
	public void buildWhenAuthorizationCodeGrantClientAuthenticationMethodNotProvidedAndClientSecretNullThenDefaultToNone() {
		// @formatter:off
		ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.clientSecret(null)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUri(REDIRECT_URI)
				.scope(SCOPES.toArray(new String[0]))
				.authorizationUri(AUTHORIZATION_URI)
				.tokenUri(TOKEN_URI)
				.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
				.jwkSetUri(JWK_SET_URI)
				.clientName(CLIENT_NAME)
				.build();
		// @formatter:on
		assertThat(clientRegistration.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.NONE);
	}

	@Test
	public void buildWhenAuthorizationCodeGrantClientAuthenticationMethodNotProvidedAndClientSecretBlankThenDefaultToNone() {
		// @formatter:off
		ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.clientSecret(" ")
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUri(REDIRECT_URI)
				.scope(SCOPES.toArray(new String[0]))
				.authorizationUri(AUTHORIZATION_URI)
				.tokenUri(TOKEN_URI)
				.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
				.jwkSetUri(JWK_SET_URI)
				.clientName(CLIENT_NAME)
				.build();
		// @formatter:on
		assertThat(clientRegistration.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.NONE);
		assertThat(clientRegistration.getClientSecret()).isEqualTo("");
	}

	@Test
	public void buildWhenAuthorizationCodeGrantRedirectUriIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() ->
		// @formatter:off
			ClientRegistration.withRegistrationId(REGISTRATION_ID)
					.clientId(CLIENT_ID)
					.clientSecret(CLIENT_SECRET)
					.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
					.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
					.redirectUri(null)
					.scope(SCOPES.toArray(new String[0]))
					.authorizationUri(AUTHORIZATION_URI)
					.tokenUri(TOKEN_URI)
					.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
					.jwkSetUri(JWK_SET_URI)
					.clientName(CLIENT_NAME)
					.build()
		// @formatter:on
		);
	}

	// gh-5494
	@Test
	public void buildWhenAuthorizationCodeGrantScopeIsNullThenScopeNotRequired() {
		// @formatter:off
		ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUri(REDIRECT_URI)
				.scope((String[]) null)
				.authorizationUri(AUTHORIZATION_URI)
				.tokenUri(TOKEN_URI)
				.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
				.jwkSetUri(JWK_SET_URI)
				.clientName(CLIENT_NAME)
				.build();
		// @formatter:on
	}

	@Test
	public void buildWhenAuthorizationCodeGrantAuthorizationUriIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() ->
		// @formatter:off
			ClientRegistration.withRegistrationId(REGISTRATION_ID)
					.clientId(CLIENT_ID)
					.clientSecret(CLIENT_SECRET)
					.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
					.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
					.redirectUri(REDIRECT_URI)
					.scope(SCOPES.toArray(new String[0]))
					.authorizationUri(null)
					.tokenUri(TOKEN_URI)
					.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
					.jwkSetUri(JWK_SET_URI)
					.clientName(CLIENT_NAME)
					.build()
		// @formatter:on
		);
	}

	@Test
	public void buildWhenAuthorizationCodeGrantTokenUriIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() ->
		// @formatter:off
			ClientRegistration.withRegistrationId(REGISTRATION_ID)
					.clientId(CLIENT_ID)
					.clientSecret(CLIENT_SECRET)
					.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
					.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
					.redirectUri(REDIRECT_URI)
					.scope(SCOPES.toArray(new String[0]))
					.authorizationUri(AUTHORIZATION_URI)
					.tokenUri(null)
					.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
					.jwkSetUri(JWK_SET_URI)
					.clientName(CLIENT_NAME)
					.build()
		// @formatter:on
		);
	}

	@Test
	public void buildWhenAuthorizationCodeGrantClientNameNotProvidedThenDefaultToRegistrationId() {
		// @formatter:off
		ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUri(REDIRECT_URI)
				.scope(SCOPES.toArray(new String[0]))
				.authorizationUri(AUTHORIZATION_URI)
				.tokenUri(TOKEN_URI)
				.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
				.jwkSetUri(JWK_SET_URI)
				.build();
		// @formatter:on
		assertThat(clientRegistration.getClientName()).isEqualTo(clientRegistration.getRegistrationId());
	}

	@Test
	public void buildWhenAuthorizationCodeGrantScopeDoesNotContainOpenidThenJwkSetUriNotRequired() {
		// @formatter:off
		ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUri(REDIRECT_URI)
				.scope("scope1")
				.authorizationUri(AUTHORIZATION_URI)
				.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
				.tokenUri(TOKEN_URI)
				.clientName(CLIENT_NAME)
				.build();
		// @formatter:on
	}

	// gh-5494
	@Test
	public void buildWhenAuthorizationCodeGrantScopeIsNullThenJwkSetUriNotRequired() {
		// @formatter:off
		ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUri(REDIRECT_URI)
				.authorizationUri(AUTHORIZATION_URI)
				.tokenUri(TOKEN_URI)
				.clientName(CLIENT_NAME)
				.build();
		// @formatter:on
	}

	@Test
	public void buildWhenAuthorizationCodeGrantProviderConfigurationMetadataIsNullThenDefaultToEmpty() {
		// @formatter:off
		ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUri(REDIRECT_URI)
				.scope(SCOPES.toArray(new String[0]))
				.authorizationUri(AUTHORIZATION_URI)
				.tokenUri(TOKEN_URI)
				.userInfoAuthenticationMethod(AuthenticationMethod.HEADER)
				.providerConfigurationMetadata(null)
				.jwkSetUri(JWK_SET_URI)
				.clientName(CLIENT_NAME)
				.build();
		// @formatter:on
		assertThat(clientRegistration.getProviderDetails().getConfigurationMetadata()).isNotNull();
		assertThat(clientRegistration.getProviderDetails().getConfigurationMetadata()).isEmpty();
	}

	@Test
	public void buildWhenAuthorizationCodeGrantProviderConfigurationMetadataEmptyThenIsEmpty() {
		// @formatter:off
		ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUri(REDIRECT_URI)
				.scope(SCOPES.toArray(new String[0]))
				.authorizationUri(AUTHORIZATION_URI)
				.tokenUri(TOKEN_URI)
				.userInfoAuthenticationMethod(AuthenticationMethod.HEADER)
				.providerConfigurationMetadata(Collections.emptyMap())
				.jwkSetUri(JWK_SET_URI)
				.clientName(CLIENT_NAME)
				.build();
		// @formatter:on
		assertThat(clientRegistration.getProviderDetails().getConfigurationMetadata()).isNotNull();
		assertThat(clientRegistration.getProviderDetails().getConfigurationMetadata()).isEmpty();
	}

	@Test
	public void buildWhenImplicitGrantAllAttributesProvidedThenAllAttributesAreSet() {
		// @formatter:off
		ClientRegistration registration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.authorizationGrantType(AuthorizationGrantType.IMPLICIT)
				.redirectUri(REDIRECT_URI)
				.scope(SCOPES.toArray(new String[0]))
				.authorizationUri(AUTHORIZATION_URI)
				.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
				.clientName(CLIENT_NAME)
				.build();
		// @formatter:on
		assertThat(registration.getRegistrationId()).isEqualTo(REGISTRATION_ID);
		assertThat(registration.getClientId()).isEqualTo(CLIENT_ID);
		assertThat(registration.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.IMPLICIT);
		assertThat(registration.getRedirectUri()).isEqualTo(REDIRECT_URI);
		assertThat(registration.getScopes()).isEqualTo(SCOPES);
		assertThat(registration.getProviderDetails().getAuthorizationUri()).isEqualTo(AUTHORIZATION_URI);
		assertThat(registration.getProviderDetails().getUserInfoEndpoint().getAuthenticationMethod())
				.isEqualTo(AuthenticationMethod.FORM);
		assertThat(registration.getClientName()).isEqualTo(CLIENT_NAME);
	}

	@Test
	public void buildWhenImplicitGrantRegistrationIdIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() ->
		// @formatter:off
			ClientRegistration.withRegistrationId(null)
					.clientId(CLIENT_ID)
					.authorizationGrantType(AuthorizationGrantType.IMPLICIT)
					.redirectUri(REDIRECT_URI)
					.scope(SCOPES.toArray(new String[0]))
					.authorizationUri(AUTHORIZATION_URI)
					.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
					.clientName(CLIENT_NAME)
					.build()
		// @formatter:on
		);
	}

	@Test
	public void buildWhenImplicitGrantClientIdIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() ->
		// @formatter:off
			ClientRegistration.withRegistrationId(REGISTRATION_ID)
					.clientId(null)
					.authorizationGrantType(AuthorizationGrantType.IMPLICIT)
					.redirectUri(REDIRECT_URI)
					.scope(SCOPES.toArray(new String[0]))
					.authorizationUri(AUTHORIZATION_URI)
					.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
					.clientName(CLIENT_NAME)
					.build()
		// @formatter:on
		);
	}

	@Test
	public void buildWhenImplicitGrantRedirectUriIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() ->
		// @formatter:off
			ClientRegistration.withRegistrationId(REGISTRATION_ID)
					.clientId(CLIENT_ID)
					.authorizationGrantType(AuthorizationGrantType.IMPLICIT)
					.redirectUri(null)
					.scope(SCOPES.toArray(new String[0]))
					.authorizationUri(AUTHORIZATION_URI)
					.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
					.clientName(CLIENT_NAME)
					.build()
		// @formatter:on
		);
	}

	// gh-5494
	@Test
	public void buildWhenImplicitGrantScopeIsNullThenScopeNotRequired() {
		// @formatter:off
		ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.authorizationGrantType(AuthorizationGrantType.IMPLICIT)
				.redirectUri(REDIRECT_URI)
				.scope((String[]) null)
				.authorizationUri(AUTHORIZATION_URI)
				.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
				.clientName(CLIENT_NAME)
				.build();
		// @formatter:on
	}

	@Test
	public void buildWhenImplicitGrantAuthorizationUriIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() ->
		// @formatter:off
			ClientRegistration.withRegistrationId(REGISTRATION_ID)
					.clientId(CLIENT_ID)
					.authorizationGrantType(AuthorizationGrantType.IMPLICIT)
					.redirectUri(REDIRECT_URI)
					.scope(SCOPES.toArray(new String[0]))
					.authorizationUri(null)
					.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
					.clientName(CLIENT_NAME)
					.build()
		// @formatter:on
		);
	}

	@Test
	public void buildWhenImplicitGrantClientNameNotProvidedThenDefaultToRegistrationId() {
		// @formatter:off
		ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.authorizationGrantType(AuthorizationGrantType.IMPLICIT)
				.redirectUri(REDIRECT_URI)
				.scope(SCOPES.toArray(new String[0]))
				.authorizationUri(AUTHORIZATION_URI)
				.userInfoAuthenticationMethod(AuthenticationMethod.FORM)
				.build();
		// @formatter:on
		assertThat(clientRegistration.getClientName()).isEqualTo(clientRegistration.getRegistrationId());
	}

	@Test
	public void buildWhenOverrideRegistrationIdThenOverridden() {
		String overriddenId = "override";
		// @formatter:off
		ClientRegistration registration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.registrationId(overriddenId)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUri(REDIRECT_URI)
				.scope(SCOPES.toArray(new String[0]))
				.authorizationUri(AUTHORIZATION_URI)
				.tokenUri(TOKEN_URI)
				.jwkSetUri(JWK_SET_URI)
				.clientName(CLIENT_NAME)
				.build();
		// @formatter:on
		assertThat(registration.getRegistrationId()).isEqualTo(overriddenId);
	}

	@Test
	public void buildWhenClientCredentialsGrantAllAttributesProvidedThenAllAttributesAreSet() {
		// @formatter:off
		ClientRegistration registration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.scope(SCOPES.toArray(new String[0]))
				.tokenUri(TOKEN_URI)
				.clientName(CLIENT_NAME)
				.build();
		// @formatter:on
		assertThat(registration.getRegistrationId()).isEqualTo(REGISTRATION_ID);
		assertThat(registration.getClientId()).isEqualTo(CLIENT_ID);
		assertThat(registration.getClientSecret()).isEqualTo(CLIENT_SECRET);
		assertThat(registration.getClientAuthenticationMethod())
				.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
		assertThat(registration.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.CLIENT_CREDENTIALS);
		assertThat(registration.getScopes()).isEqualTo(SCOPES);
		assertThat(registration.getProviderDetails().getTokenUri()).isEqualTo(TOKEN_URI);
		assertThat(registration.getClientName()).isEqualTo(CLIENT_NAME);
	}

	@Test
	public void buildWhenClientCredentialsGrantRegistrationIdIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(
				() -> ClientRegistration.withRegistrationId(null).clientId(CLIENT_ID).clientSecret(CLIENT_SECRET)
						.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
						.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).tokenUri(TOKEN_URI).build());
	}

	@Test
	public void buildWhenClientCredentialsGrantClientIdIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(
				() -> ClientRegistration.withRegistrationId(REGISTRATION_ID).clientId(null).clientSecret(CLIENT_SECRET)
						.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
						.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).tokenUri(TOKEN_URI).build());
	}

	@Test
	public void buildWhenClientCredentialsGrantClientSecretIsNullThenDefaultToEmpty() {
		// @formatter:off
		ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.clientSecret(null)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.tokenUri(TOKEN_URI)
				.build();
		// @formatter:on
		assertThat(clientRegistration.getClientSecret()).isEqualTo("");
	}

	@Test
	public void buildWhenClientCredentialsGrantClientAuthenticationMethodNotProvidedThenDefaultToBasic() {
		// @formatter:off
		ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.tokenUri(TOKEN_URI)
				.build();
		// @formatter:on
		assertThat(clientRegistration.getClientAuthenticationMethod())
				.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
	}

	@Test
	public void buildWhenClientCredentialsGrantTokenUriIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID).clientSecret(CLIENT_SECRET)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).tokenUri(null).build());
	}

	// gh-6256
	@Test
	public void buildWhenScopesContainASpaceThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> TestClientRegistrations.clientCredentials().scope("openid profile email").build());
	}

	@Test
	public void buildWhenScopesContainAnInvalidCharacterThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> TestClientRegistrations.clientCredentials().scope("an\"invalid\"scope").build());
	}

	@Test
	public void buildWhenPasswordGrantAllAttributesProvidedThenAllAttributesAreSet() {
		// @formatter:off
		ClientRegistration registration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.PASSWORD)
				.scope(SCOPES.toArray(new String[0]))
				.tokenUri(TOKEN_URI)
				.clientName(CLIENT_NAME)
				.build();
		// @formatter:on
		assertThat(registration.getRegistrationId()).isEqualTo(REGISTRATION_ID);
		assertThat(registration.getClientId()).isEqualTo(CLIENT_ID);
		assertThat(registration.getClientSecret()).isEqualTo(CLIENT_SECRET);
		assertThat(registration.getClientAuthenticationMethod())
				.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
		assertThat(registration.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.PASSWORD);
		assertThat(registration.getScopes()).isEqualTo(SCOPES);
		assertThat(registration.getProviderDetails().getTokenUri()).isEqualTo(TOKEN_URI);
		assertThat(registration.getClientName()).isEqualTo(CLIENT_NAME);
	}

	@Test
	public void buildWhenPasswordGrantRegistrationIdIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> ClientRegistration.withRegistrationId(null)
						.clientId(CLIENT_ID)
						.clientSecret(CLIENT_SECRET)
						.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
						.authorizationGrantType(AuthorizationGrantType.PASSWORD)
						.tokenUri(TOKEN_URI)
						.build()
				);
		// @formatter:on
	}

	@Test
	public void buildWhenPasswordGrantClientIdIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException().isThrownBy(() -> ClientRegistration
				.withRegistrationId(REGISTRATION_ID)
				.clientId(null)
				.clientSecret(CLIENT_SECRET)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.PASSWORD)
				.tokenUri(TOKEN_URI)
				.build()
		);
		// @formatter:on
	}

	@Test
	public void buildWhenPasswordGrantClientSecretIsNullThenDefaultToEmpty() {
		// @formatter:off
		ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.clientSecret(null)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.PASSWORD)
				.tokenUri(TOKEN_URI)
				.build();
		// @formatter:on
		assertThat(clientRegistration.getClientSecret()).isEqualTo("");
	}

	@Test
	public void buildWhenPasswordGrantClientAuthenticationMethodNotProvidedThenDefaultToBasic() {
		// @formatter:off
		ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.authorizationGrantType(AuthorizationGrantType.PASSWORD)
				.tokenUri(TOKEN_URI)
				.build();
		// @formatter:on
		assertThat(clientRegistration.getClientAuthenticationMethod())
				.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
	}

	@Test
	public void buildWhenPasswordGrantTokenUriIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> ClientRegistration.withRegistrationId(REGISTRATION_ID)
						.clientId(CLIENT_ID)
						.clientSecret(CLIENT_SECRET)
						.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
						.authorizationGrantType(AuthorizationGrantType.PASSWORD)
						.tokenUri(null)
						.build()
				);
		// @formatter:on
	}

	@Test
	public void buildWhenCustomGrantAllAttributesProvidedThenAllAttributesAreSet() {
		AuthorizationGrantType customGrantType = new AuthorizationGrantType("CUSTOM");
		// @formatter:off
		ClientRegistration registration = ClientRegistration
				.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(customGrantType)
				.scope(SCOPES.toArray(new String[0]))
				.tokenUri(TOKEN_URI)
				.clientName(CLIENT_NAME)
				.build();
		// @formatter:on
		assertThat(registration.getRegistrationId()).isEqualTo(REGISTRATION_ID);
		assertThat(registration.getClientId()).isEqualTo(CLIENT_ID);
		assertThat(registration.getClientSecret()).isEqualTo(CLIENT_SECRET);
		assertThat(registration.getClientAuthenticationMethod())
				.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
		assertThat(registration.getAuthorizationGrantType()).isEqualTo(customGrantType);
		assertThat(registration.getScopes()).isEqualTo(SCOPES);
		assertThat(registration.getProviderDetails().getTokenUri()).isEqualTo(TOKEN_URI);
		assertThat(registration.getClientName()).isEqualTo(CLIENT_NAME);
	}

	@Test
	public void buildWhenClientRegistrationProvidedThenMakesACopy() {
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();
		ClientRegistration updated = ClientRegistration.withClientRegistration(clientRegistration).build();
		assertThat(clientRegistration.getScopes()).isEqualTo(updated.getScopes());
		assertThat(clientRegistration.getScopes()).isNotSameAs(updated.getScopes());
		assertThat(clientRegistration.getProviderDetails().getConfigurationMetadata())
				.isEqualTo(updated.getProviderDetails().getConfigurationMetadata());
		assertThat(clientRegistration.getProviderDetails().getConfigurationMetadata())
				.isNotSameAs(updated.getProviderDetails().getConfigurationMetadata());
	}

	@Test
	public void buildWhenClientRegistrationProvidedThenEachPropertyMatches() {
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();
		ClientRegistration updated = ClientRegistration.withClientRegistration(clientRegistration).build();
		assertThat(clientRegistration.getRegistrationId()).isEqualTo(updated.getRegistrationId());
		assertThat(clientRegistration.getClientId()).isEqualTo(updated.getClientId());
		assertThat(clientRegistration.getClientSecret()).isEqualTo(updated.getClientSecret());
		assertThat(clientRegistration.getClientAuthenticationMethod())
				.isEqualTo(updated.getClientAuthenticationMethod());
		assertThat(clientRegistration.getAuthorizationGrantType()).isEqualTo(updated.getAuthorizationGrantType());
		assertThat(clientRegistration.getRedirectUri()).isEqualTo(updated.getRedirectUri());
		assertThat(clientRegistration.getScopes()).isEqualTo(updated.getScopes());
		ClientRegistration.ProviderDetails providerDetails = clientRegistration.getProviderDetails();
		ClientRegistration.ProviderDetails updatedProviderDetails = updated.getProviderDetails();
		assertThat(providerDetails.getAuthorizationUri()).isEqualTo(updatedProviderDetails.getAuthorizationUri());
		assertThat(providerDetails.getTokenUri()).isEqualTo(updatedProviderDetails.getTokenUri());
		ClientRegistration.ProviderDetails.UserInfoEndpoint userInfoEndpoint = providerDetails.getUserInfoEndpoint();
		ClientRegistration.ProviderDetails.UserInfoEndpoint updatedUserInfoEndpoint = updatedProviderDetails
				.getUserInfoEndpoint();
		assertThat(userInfoEndpoint.getUri()).isEqualTo(updatedUserInfoEndpoint.getUri());
		assertThat(userInfoEndpoint.getAuthenticationMethod())
				.isEqualTo(updatedUserInfoEndpoint.getAuthenticationMethod());
		assertThat(userInfoEndpoint.getUserNameAttributeName())
				.isEqualTo(updatedUserInfoEndpoint.getUserNameAttributeName());
		assertThat(providerDetails.getJwkSetUri()).isEqualTo(updatedProviderDetails.getJwkSetUri());
		assertThat(providerDetails.getIssuerUri()).isEqualTo(updatedProviderDetails.getIssuerUri());
		assertThat(providerDetails.getConfigurationMetadata())
				.isEqualTo(updatedProviderDetails.getConfigurationMetadata());
		assertThat(clientRegistration.getClientName()).isEqualTo(updated.getClientName());
	}

	@Test
	public void buildWhenClientRegistrationValuesOverriddenThenPropagated() {
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();
		// @formatter:off
		ClientRegistration updated = ClientRegistration.withClientRegistration(clientRegistration)
				.clientSecret("a-new-secret")
				.scope("a-new-scope")
				.providerConfigurationMetadata(Collections.singletonMap("a-new-config", "a-new-value"))
				.build();
		// @formatter:on
		assertThat(clientRegistration.getClientSecret()).isNotEqualTo(updated.getClientSecret());
		assertThat(updated.getClientSecret()).isEqualTo("a-new-secret");
		assertThat(clientRegistration.getScopes()).doesNotContain("a-new-scope");
		assertThat(updated.getScopes()).containsExactly("a-new-scope");
		assertThat(clientRegistration.getProviderDetails().getConfigurationMetadata()).doesNotContainKey("a-new-config")
				.doesNotContainValue("a-new-value");
		assertThat(updated.getProviderDetails().getConfigurationMetadata()).containsOnlyKeys("a-new-config")
				.containsValue("a-new-value");
	}

	// gh-8903
	@Test
	public void buildWhenCustomClientAuthenticationMethodProvidedThenSet() {
		ClientAuthenticationMethod clientAuthenticationMethod = new ClientAuthenticationMethod("tls_client_auth");
		// @formatter:off
		ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(REGISTRATION_ID)
				.clientId(CLIENT_ID)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.clientAuthenticationMethod(clientAuthenticationMethod)
				.redirectUri(REDIRECT_URI)
				.authorizationUri(AUTHORIZATION_URI)
				.tokenUri(TOKEN_URI)
				.build();
		// @formatter:on
		assertThat(clientRegistration.getClientAuthenticationMethod()).isEqualTo(clientAuthenticationMethod);
	}

}
