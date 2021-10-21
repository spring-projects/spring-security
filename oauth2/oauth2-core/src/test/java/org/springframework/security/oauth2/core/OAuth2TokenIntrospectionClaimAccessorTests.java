/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.oauth2.core;

import java.net.MalformedURLException;
import java.net.URL;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

/**
 * Tests for {@link OAuth2TokenIntrospectionClaimAccessor}.
 *
 * @author David Kovac
 */
public class OAuth2TokenIntrospectionClaimAccessorTests {

	private final Map<String, Object> claims = new HashMap<>();

	private final OAuth2TokenIntrospectionClaimAccessor claimAccessor = (() -> this.claims);

	@BeforeEach
	public void setup() {
		this.claims.clear();
	}

	@Test
	public void isActiveWhenActiveClaimNotExistingThenReturnFalse() {
		assertThat(this.claimAccessor.isActive()).isFalse();
	}

	@Test
	public void isActiveWhenActiveClaimValueIsNullThenThrowsNullPointerException() {
		this.claims.put(OAuth2TokenIntrospectionClaimNames.ACTIVE, null);
		assertThatNullPointerException().isThrownBy(this.claimAccessor::isActive);
	}

	@Test
	public void isActiveWhenActiveClaimValueIsTrueThenReturnTrue() {
		this.claims.put(OAuth2TokenIntrospectionClaimNames.ACTIVE, "true");
		assertThat(this.claimAccessor.isActive()).isTrue();
	}

	@Test
	public void getUsernameWhenUsernameClaimNotExistingThenReturnNull() {
		assertThat(this.claimAccessor.getUsername()).isNull();
	}

	@Test
	public void getUsernameWhenUsernameClaimExistingThenReturnUsername() {
		String expectedUsernameValue = "username";
		this.claims.put(OAuth2TokenIntrospectionClaimNames.USERNAME, expectedUsernameValue);
		assertThat(this.claimAccessor.getUsername()).isEqualTo(expectedUsernameValue);
	}

	@Test
	public void getClientIdWhenClientIdClaimNotExistingThenReturnNull() {
		assertThat(this.claimAccessor.getUsername()).isNull();
	}

	@Test
	public void getClientIdWhenClientIdClaimExistingThenReturnClientId() {
		String expectedClientIdValue = "clientId";
		this.claims.put(OAuth2TokenIntrospectionClaimNames.CLIENT_ID, expectedClientIdValue);
		assertThat(this.claimAccessor.getClientId()).isEqualTo(expectedClientIdValue);
	}

	@Test
	public void getScopesWhenScopeClaimNotExistingThenReturnNull() {
		assertThat(this.claimAccessor.getScopes()).isNull();
	}

	@Test
	public void getScopesWhenScopeClaimExistingThenReturnScope() {
		List<String> expectedScopeValue = Arrays.asList("scope1", "scope2");
		this.claims.put(OAuth2TokenIntrospectionClaimNames.SCOPE, expectedScopeValue);
		assertThat(this.claimAccessor.getScopes()).hasSameElementsAs(expectedScopeValue);
	}

	@Test
	public void getTokenTypeWhenTokenTypeClaimNotExistingThenReturnNull() {
		assertThat(this.claimAccessor.getTokenType()).isNull();
	}

	@Test
	public void getTokenTypeWhenTokenTypeClaimExistingThenReturnTokenType() {
		String expectedTokenTypeValue = "tokenType";
		this.claims.put(OAuth2TokenIntrospectionClaimNames.TOKEN_TYPE, expectedTokenTypeValue);
		assertThat(this.claimAccessor.getTokenType()).isEqualTo(expectedTokenTypeValue);
	}

	@Test
	public void getExpiresAtWhenExpiresAtClaimNotExistingThenReturnNull() {
		assertThat(this.claimAccessor.getExpiresAt()).isNull();
	}

	@Test
	public void getExpiresAtWhenExpiresAtClaimExistingThenReturnExpiresAt() {
		Instant expectedExpiresAtValue = Instant.now();
		this.claims.put(OAuth2TokenIntrospectionClaimNames.EXP, expectedExpiresAtValue);
		assertThat(this.claimAccessor.getExpiresAt()).isEqualTo(expectedExpiresAtValue);
	}

	@Test
	public void getIssuedAtWhenIssuedAtClaimNotExistingThenReturnNull() {
		assertThat(this.claimAccessor.getExpiresAt()).isNull();
	}

	@Test
	public void getIssuedAtWhenIssuedAtClaimExistingThenReturnIssuedAt() {
		Instant expectedIssuedAtValue = Instant.now();
		this.claims.put(OAuth2TokenIntrospectionClaimNames.IAT, expectedIssuedAtValue);
		assertThat(this.claimAccessor.getIssuedAt()).isEqualTo(expectedIssuedAtValue);
	}

	@Test
	public void getNotBeforeWhenNotBeforeClaimNotExistingThenReturnNull() {
		assertThat(this.claimAccessor.getNotBefore()).isNull();
	}

	@Test
	public void getNotBeforeWhenNotBeforeClaimExistingThenReturnNotBefore() {
		Instant expectedNotBeforeValue = Instant.now();
		this.claims.put(OAuth2TokenIntrospectionClaimNames.NBF, expectedNotBeforeValue);
		assertThat(this.claimAccessor.getNotBefore()).isEqualTo(expectedNotBeforeValue);
	}

	@Test
	public void getSubjectWhenSubjectClaimNotExistingThenReturnNull() {
		assertThat(this.claimAccessor.getSubject()).isNull();
	}

	@Test
	public void getSubjectWhenSubjectClaimExistingThenReturnSubject() {
		String expectedSubjectValue = "subject";
		this.claims.put(OAuth2TokenIntrospectionClaimNames.SUB, expectedSubjectValue);
		assertThat(this.claimAccessor.getSubject()).isEqualTo(expectedSubjectValue);
	}

	@Test
	public void getAudienceWhenAudienceClaimNotExistingThenReturnNull() {
		assertThat(this.claimAccessor.getAudience()).isNull();
	}

	@Test
	public void getAudienceWhenAudienceClaimExistingThenReturnAudience() {
		List<String> expectedAudienceValue = Arrays.asList("audience1", "audience2");
		this.claims.put(OAuth2TokenIntrospectionClaimNames.AUD, expectedAudienceValue);
		assertThat(this.claimAccessor.getAudience()).hasSameElementsAs(expectedAudienceValue);
	}

	@Test
	public void getIssuerWhenIssuerClaimNotExistingThenReturnNull() {
		assertThat(this.claimAccessor.getIssuer()).isNull();
	}

	@Test
	public void getIssuerWhenIssuerClaimExistingThenReturnIssuer() throws MalformedURLException {
		URL expectedIssuerValue = new URL("https://issuer.com");
		this.claims.put(OAuth2TokenIntrospectionClaimNames.ISS, expectedIssuerValue);
		assertThat(this.claimAccessor.getIssuer()).isEqualTo(expectedIssuerValue);
	}

	@Test
	public void getIdWhenJtiClaimNotExistingThenReturnNull() {
		assertThat(this.claimAccessor.getId()).isNull();
	}

	@Test
	public void getIdWhenJtiClaimExistingThenReturnId() {
		String expectedIdValue = "id";
		this.claims.put(OAuth2TokenIntrospectionClaimNames.JTI, expectedIdValue);
		assertThat(this.claimAccessor.getId()).isEqualTo(expectedIdValue);
	}

}
