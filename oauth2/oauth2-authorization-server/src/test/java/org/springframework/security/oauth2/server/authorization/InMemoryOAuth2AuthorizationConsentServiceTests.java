/*
 * Copyright 2020-2022 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link InMemoryOAuth2AuthorizationConsentService}.
 *
 * @author Daniel Garnier-Moiroux
 */
public class InMemoryOAuth2AuthorizationConsentServiceTests {

	private static final String REGISTERED_CLIENT_ID = "registered-client-id";

	private static final String PRINCIPAL_NAME = "principal-name";

	private static final OAuth2AuthorizationConsent AUTHORIZATION_CONSENT = OAuth2AuthorizationConsent
		.withId(REGISTERED_CLIENT_ID, PRINCIPAL_NAME)
		.authority(new SimpleGrantedAuthority("some.authority"))
		.build();

	private InMemoryOAuth2AuthorizationConsentService authorizationConsentService;

	@BeforeEach
	public void setUp() {
		this.authorizationConsentService = new InMemoryOAuth2AuthorizationConsentService();
		this.authorizationConsentService.save(AUTHORIZATION_CONSENT);
	}

	@Test
	public void constructorVarargsWhenAuthorizationConsentNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new InMemoryOAuth2AuthorizationConsentService((OAuth2AuthorizationConsent) null))
			.withMessage("authorizationConsent cannot be null");
	}

	@Test
	public void constructorListWhenAuthorizationConsentsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new InMemoryOAuth2AuthorizationConsentService((List<OAuth2AuthorizationConsent>) null))
			.withMessage("authorizationConsents cannot be null");
	}

	@Test
	public void constructorWhenDuplicateAuthorizationConsentsThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(
					() -> new InMemoryOAuth2AuthorizationConsentService(AUTHORIZATION_CONSENT, AUTHORIZATION_CONSENT))
			.withMessage(
					"The authorizationConsent must be unique. Found duplicate, with registered client id: [registered-client-id] and principal name: [principal-name]");
	}

	@Test
	public void saveWhenAuthorizationConsentNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.authorizationConsentService.save(null))
			.withMessage("authorizationConsent cannot be null");
	}

	@Test
	public void saveWhenAuthorizationConsentNewThenSaved() {
		OAuth2AuthorizationConsent expectedAuthorizationConsent = OAuth2AuthorizationConsent
			.withId("new-client", "new-principal")
			.authority(new SimpleGrantedAuthority("new.authority"))
			.build();

		this.authorizationConsentService.save(expectedAuthorizationConsent);

		OAuth2AuthorizationConsent authorizationConsent = this.authorizationConsentService.findById("new-client",
				"new-principal");
		assertThat(authorizationConsent).isEqualTo(expectedAuthorizationConsent);
	}

	@Test
	public void saveWhenAuthorizationConsentExistsThenUpdated() {
		OAuth2AuthorizationConsent expectedAuthorizationConsent = OAuth2AuthorizationConsent.from(AUTHORIZATION_CONSENT)
			.authority(new SimpleGrantedAuthority("new.authority"))
			.build();

		this.authorizationConsentService.save(expectedAuthorizationConsent);

		OAuth2AuthorizationConsent authorizationConsent = this.authorizationConsentService
			.findById(AUTHORIZATION_CONSENT.getRegisteredClientId(), AUTHORIZATION_CONSENT.getPrincipalName());
		assertThat(authorizationConsent).isEqualTo(expectedAuthorizationConsent);
		assertThat(authorizationConsent).isNotEqualTo(AUTHORIZATION_CONSENT);
	}

	@Test
	public void removeWhenAuthorizationConsentNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.authorizationConsentService.remove(null))
			.withMessage("authorizationConsent cannot be null");
	}

	@Test
	public void removeWhenAuthorizationConsentProvidedThenRemoved() {
		this.authorizationConsentService.remove(AUTHORIZATION_CONSENT);
		assertThat(this.authorizationConsentService.findById(AUTHORIZATION_CONSENT.getRegisteredClientId(),
				AUTHORIZATION_CONSENT.getPrincipalName()))
			.isNull();
	}

	@Test
	public void findByIdWhenRegisteredClientIdNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.authorizationConsentService.findById(null, "some-user"))
			.withMessage("registeredClientId cannot be empty");
	}

	@Test
	public void findByIdWhenPrincipalNameNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.authorizationConsentService.findById("some-client", null))
			.withMessage("principalName cannot be empty");
	}

	@Test
	public void findByIdWhenAuthorizationConsentExistsThenFound() {
		assertThat(this.authorizationConsentService.findById(REGISTERED_CLIENT_ID, PRINCIPAL_NAME))
			.isEqualTo(AUTHORIZATION_CONSENT);
	}

	@Test
	public void findByIdWhenAuthorizationConsentDoesNotExistThenNull() {
		this.authorizationConsentService.save(AUTHORIZATION_CONSENT);
		assertThat(this.authorizationConsentService.findById("unknown-client", PRINCIPAL_NAME)).isNull();
		assertThat(this.authorizationConsentService.findById(REGISTERED_CLIENT_ID, "unknown-user")).isNull();
	}

}
