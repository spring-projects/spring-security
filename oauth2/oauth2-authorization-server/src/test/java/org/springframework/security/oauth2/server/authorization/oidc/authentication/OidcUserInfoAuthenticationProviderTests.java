/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.oauth2.server.authorization.oidc.authentication;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JoseHeaderNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link OidcUserInfoAuthenticationProvider}.
 *
 * @author Steve Riesenberg
 */
public class OidcUserInfoAuthenticationProviderTests {

	private OAuth2AuthorizationService authorizationService;

	private OidcUserInfoAuthenticationProvider authenticationProvider;

	@BeforeEach
	public void setUp() {
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.authenticationProvider = new OidcUserInfoAuthenticationProvider(this.authorizationService);
	}

	@Test
	public void constructorWhenAuthorizationServiceNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new OidcUserInfoAuthenticationProvider(null))
			.withMessage("authorizationService cannot be null");
	}

	@Test
	public void setUserInfoMapperWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.authenticationProvider.setUserInfoMapper(null))
			.withMessage("userInfoMapper cannot be null");
	}

	@Test
	public void supportsWhenTypeOidcUserInfoAuthenticationTokenThenReturnTrue() {
		assertThat(this.authenticationProvider.supports(OidcUserInfoAuthenticationToken.class)).isTrue();
	}

	@Test
	public void authenticateWhenPrincipalNotOfExpectedTypeThenThrowOAuth2AuthenticationException() {
		OidcUserInfoAuthenticationToken authentication = new OidcUserInfoAuthenticationToken(
				new UsernamePasswordAuthenticationToken(null, null));

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);

		verifyNoInteractions(this.authorizationService);
	}

	@Test
	public void authenticateWhenPrincipalNotAuthenticatedThenThrowOAuth2AuthenticationException() {
		String tokenValue = "token";
		JwtAuthenticationToken principal = createJwtAuthenticationToken(tokenValue);
		principal.setAuthenticated(false);
		OidcUserInfoAuthenticationToken authentication = new OidcUserInfoAuthenticationToken(principal);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);

		verifyNoInteractions(this.authorizationService);
	}

	@Test
	public void authenticateWhenAccessTokenNotFoundThenThrowOAuth2AuthenticationException() {
		String tokenValue = "token";
		JwtAuthenticationToken principal = createJwtAuthenticationToken(tokenValue);
		OidcUserInfoAuthenticationToken authentication = new OidcUserInfoAuthenticationToken(principal);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);

		verify(this.authorizationService).findByToken(eq(tokenValue), eq(OAuth2TokenType.ACCESS_TOKEN));
	}

	@Test
	public void authenticateWhenAccessTokenNotActiveThenThrowOAuth2AuthenticationException() {
		String tokenValue = "token";
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization().build();
		authorization = OAuth2Authorization.from(authorization)
			.invalidate(authorization.getAccessToken().getToken())
			.build();
		given(this.authorizationService.findByToken(eq(tokenValue), eq(OAuth2TokenType.ACCESS_TOKEN)))
			.willReturn(authorization);

		JwtAuthenticationToken principal = createJwtAuthenticationToken(tokenValue);
		OidcUserInfoAuthenticationToken authentication = new OidcUserInfoAuthenticationToken(principal);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);

		verify(this.authorizationService).findByToken(eq(tokenValue), eq(OAuth2TokenType.ACCESS_TOKEN));
	}

	@Test
	public void authenticateWhenAccessTokenNotAuthorizedThenThrowOAuth2AuthenticationException() {
		String tokenValue = "token";
		given(this.authorizationService.findByToken(eq(tokenValue), eq(OAuth2TokenType.ACCESS_TOKEN)))
			.willReturn(TestOAuth2Authorizations.authorization().build());

		JwtAuthenticationToken principal = createJwtAuthenticationToken(tokenValue);
		OidcUserInfoAuthenticationToken authentication = new OidcUserInfoAuthenticationToken(principal);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INSUFFICIENT_SCOPE);

		verify(this.authorizationService).findByToken(eq(tokenValue), eq(OAuth2TokenType.ACCESS_TOKEN));
	}

	@Test
	public void authenticateWhenIdTokenNullThenThrowOAuth2AuthenticationException() {
		String tokenValue = "token";
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization()
			.token(createAuthorization(tokenValue).getAccessToken().getToken())
			.build();
		given(this.authorizationService.findByToken(eq(tokenValue), eq(OAuth2TokenType.ACCESS_TOKEN)))
			.willReturn(authorization);

		JwtAuthenticationToken principal = createJwtAuthenticationToken(tokenValue);
		OidcUserInfoAuthenticationToken authentication = new OidcUserInfoAuthenticationToken(principal);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);

		verify(this.authorizationService).findByToken(eq(tokenValue), eq(OAuth2TokenType.ACCESS_TOKEN));
	}

	@Test
	public void authenticateWhenValidAccessTokenThenReturnUserInfo() {
		String tokenValue = "access-token";
		given(this.authorizationService.findByToken(eq(tokenValue), eq(OAuth2TokenType.ACCESS_TOKEN)))
			.willReturn(createAuthorization(tokenValue));

		JwtAuthenticationToken principal = createJwtAuthenticationToken(tokenValue);
		OidcUserInfoAuthenticationToken authentication = new OidcUserInfoAuthenticationToken(principal);
		OidcUserInfoAuthenticationToken authenticationResult = (OidcUserInfoAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);

		assertThat(authenticationResult.getPrincipal()).isEqualTo(principal);
		assertThat(authenticationResult.getCredentials()).isEqualTo("");
		assertThat(authenticationResult.isAuthenticated()).isTrue();

		OidcUserInfo userInfo = authenticationResult.getUserInfo();
		assertThat(userInfo.getClaims()).hasSize(20);
		assertThat(userInfo.getSubject()).isEqualTo("user1");
		assertThat(userInfo.getFullName()).isEqualTo("First Last");
		assertThat(userInfo.getGivenName()).isEqualTo("First");
		assertThat(userInfo.getFamilyName()).isEqualTo("Last");
		assertThat(userInfo.getMiddleName()).isEqualTo("Middle");
		assertThat(userInfo.getNickName()).isEqualTo("User");
		assertThat(userInfo.getPreferredUsername()).isEqualTo("user");
		assertThat(userInfo.getProfile()).isEqualTo("https://example.com/user1");
		assertThat(userInfo.getPicture()).isEqualTo("https://example.com/user1.jpg");
		assertThat(userInfo.getWebsite()).isEqualTo("https://example.com");
		assertThat(userInfo.getEmail()).isEqualTo("user1@example.com");
		assertThat(userInfo.getEmailVerified()).isEqualTo(true);
		assertThat(userInfo.getGender()).isEqualTo("female");
		assertThat(userInfo.getBirthdate()).isEqualTo("1970-01-01");
		assertThat(userInfo.getZoneInfo()).isEqualTo("Europe/Paris");
		assertThat(userInfo.getLocale()).isEqualTo("en-US");
		assertThat(userInfo.getPhoneNumber()).isEqualTo("+1 (604) 555-1234;ext=5678");
		assertThat(userInfo.getPhoneNumberVerified()).isEqualTo(false);
		assertThat(userInfo.getAddress().getFormatted())
			.isEqualTo("Champ de Mars\n5 Av. Anatole France\n75007 Paris\nFrance");
		assertThat(userInfo.getUpdatedAt()).isEqualTo(Instant.parse("1970-01-01T00:00:00Z"));

		verify(this.authorizationService).findByToken(eq(tokenValue), eq(OAuth2TokenType.ACCESS_TOKEN));
	}

	private static OAuth2Authorization createAuthorization(String tokenValue) {
		Instant now = Instant.now();
		Set<String> scopes = new HashSet<>(Arrays.asList(OidcScopes.OPENID, OidcScopes.ADDRESS, OidcScopes.EMAIL,
				OidcScopes.PHONE, OidcScopes.PROFILE));
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, tokenValue, now,
				now.plusSeconds(300), scopes);
		OidcIdToken idToken = new OidcIdToken("id-token", now, now.plusSeconds(900), createUserInfo().getClaims());

		return TestOAuth2Authorizations.authorization().token(accessToken).token(idToken).build();
	}

	private static JwtAuthenticationToken createJwtAuthenticationToken(String tokenValue) {
		Instant now = Instant.now();
		// @formatter:off
		Jwt jwt = Jwt.withTokenValue(tokenValue)
				.header(JoseHeaderNames.ALG, SignatureAlgorithm.RS256.getName())
				.issuedAt(now)
				.expiresAt(now.plusSeconds(300))
				.claim(StandardClaimNames.SUB, "user")
				.build();
		// @formatter:on
		return new JwtAuthenticationToken(jwt, Collections.emptyList());
	}

	private static OidcUserInfo createUserInfo() {
		// @formatter:off
		return OidcUserInfo.builder()
				.subject("user1")
				.name("First Last")
				.givenName("First")
				.familyName("Last")
				.middleName("Middle")
				.nickname("User")
				.preferredUsername("user")
				.profile("https://example.com/user1")
				.picture("https://example.com/user1.jpg")
				.website("https://example.com")
				.email("user1@example.com")
				.emailVerified(true)
				.gender("female")
				.birthdate("1970-01-01")
				.zoneinfo("Europe/Paris")
				.locale("en-US")
				.phoneNumber("+1 (604) 555-1234;ext=5678")
				.phoneNumberVerified(false)
				.claim("address", Collections.singletonMap("formatted", "Champ de Mars\n5 Av. Anatole France\n75007 Paris\nFrance"))
				.updatedAt("1970-01-01T00:00:00Z")
				.build();
		// @formatter:on
	}

}
