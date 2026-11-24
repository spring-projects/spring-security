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

package org.springframework.security.docs.servlet.oauth2.login.userinfojwt;

import java.time.Instant;
import java.util.Set;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OidcUserInfoJwtConfiguration} sample snippets.
 */
class OidcUserInfoJwtConfigurationTests {

	private static final String ISSUER = "https://provider.example.com";

	@Test
	void oidcUserServiceWhenSignedAndEncryptedUserInfoResponseThenLoadsUser() throws Exception {
		ECKey signingKey = new ECKeyGenerator(Curve.P_256).keyID("signing-key").generate();
		RSAKey decryptionKey = new RSAKeyGenerator(2048).keyID("decryption-key").generate();
		SignedJWT signed = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).build(),
				new JWTClaimsSet.Builder().issuer(ISSUER)
					.audience("client-id")
					.subject("user1")
					.claim("email", "user1@example.com")
					.build());
		signed.sign(new ECDSASigner(signingKey));
		JWEObject encrypted = new JWEObject(
				new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).contentType("JWT").build(),
				new Payload(signed));
		encrypted.encrypt(new RSAEncrypter(decryptionKey.toRSAPublicKey()));
		try (MockWebServer server = new MockWebServer()) {
			server.setDispatcher(provider(new JWKSet(signingKey.toPublicJWK()).toString(), encrypted.serialize()));
			OidcUser user = (OidcUser) new OidcUserInfoJwtConfiguration().oidcUserService(decryptionKey)
				.loadUser(userRequest(server));
			assertThat(user.getSubject()).isEqualTo("user1");
			assertThat(user.getEmail()).isEqualTo("user1@example.com");
		}
	}

	private static OidcUserRequest userRequest(MockWebServer server) {
		// @formatter:off
		ClientRegistration registration = ClientRegistration.withRegistrationId("provider")
			.clientId("client-id")
			.clientSecret("client-secret")
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
			.scope("openid")
			.authorizationUri(server.url("/authorize").toString())
			.tokenUri(server.url("/token").toString())
			.userInfoUri(server.url("/userinfo").toString())
			.userNameAttributeName("sub")
			.jwkSetUri(server.url("/jwks").toString())
			.issuerUri(ISSUER)
			.build();
		// @formatter:on
		Instant now = Instant.now();
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-token", now,
				now.plusSeconds(60), Set.of("openid"));
		OidcIdToken idToken = OidcIdToken.withTokenValue("id-token")
			.issuer(ISSUER)
			.subject("user1")
			.issuedAt(now)
			.expiresAt(now.plusSeconds(60))
			.build();
		return new OidcUserRequest(registration, accessToken, idToken);
	}

	private static Dispatcher provider(String jwkSet, String userInfo) {
		return new Dispatcher() {
			@Override
			public @NonNull MockResponse dispatch(@NonNull RecordedRequest request) {
				if ("/jwks".equals(request.getPath())) {
					return new MockResponse().setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
						.setBody(jwkSet);
				}
				return new MockResponse().setHeader(HttpHeaders.CONTENT_TYPE, "application/jwt").setBody(userInfo);
			}
		};
	}

}
