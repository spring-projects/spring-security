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

package org.springframework.security.oauth2.client.oidc.userinfo;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.jose.TestKeys;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link OidcUserInfoJwtDecoderFactory}.
 *
 * @author Sharang Gupta
 */
public class OidcUserInfoJwtDecoderFactoryTests {

	private static final String CLIENT_SECRET = "a-client-secret-that-is-at-least-32-bytes-long";

	private final OidcUserInfoJwtDecoderFactory factory = new OidcUserInfoJwtDecoderFactory();

	private final RSAKey encryptionRsaKey = TestJwks.generateRsa().keyID("encryption-key").build();

	private MockWebServer jwkSetServer;

	private ClientRegistration.Builder registration;

	@BeforeEach
	public void setUp() throws Exception {
		JWKSet jwkSet = new JWKSet(
				List.of(TestJwks.DEFAULT_RSA_JWK.toPublicJWK(), TestJwks.DEFAULT_EC_JWK.toPublicJWK()));
		this.jwkSetServer = new MockWebServer();
		this.jwkSetServer.setDispatcher(new Dispatcher() {
			@Override
			public @NonNull MockResponse dispatch(@NonNull RecordedRequest request) {
				return new MockResponse().setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
					.setBody(jwkSet.toString());
			}
		});
		this.jwkSetServer.start();
		this.registration = TestClientRegistrations.clientRegistration()
			.scope("openid")
			.jwkSetUri(this.jwkSetServer.url("/jwks").toString());
	}

	@AfterEach
	public void cleanup() throws Exception {
		this.jwkSetServer.shutdown();
	}

	@Test
	public void setJwsAlgorithmResolverWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.factory.setJwsAlgorithmResolver(null));
	}

	@Test
	public void setJwtValidatorFactoryWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.factory.setJwtValidatorFactory(null));
	}

	@Test
	public void setClaimTypeConverterFactoryWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.factory.setClaimTypeConverterFactory(null));
	}

	@Test
	public void setJweDecryptionKeyResolverWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.factory.setJweDecryptionKeyResolver(null));
	}

	@Test
	public void createDecoderWhenClientRegistrationNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.factory.createDecoder(null));
	}

	@Test
	public void createDecoderWhenJwkSetUriMissingThenThrowOAuth2AuthenticationException() {
		ClientRegistration clientRegistration = this.registration.jwkSetUri(null).build();
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.factory.createDecoder(clientRegistration))
			.withMessageContaining("missing_signature_verifier")
			.withMessageContaining("Check to ensure you have configured the JwkSet URI.");
	}

	@Test
	public void decodeWhenSignedWithRs256ThenClaimsAreVerifiedAndReturned() throws Exception {
		String token = signedByDefaultRsaKey(claims());
		Jwt jwt = this.factory.createDecoder(this.registration.build()).decode(token);
		assertThat(jwt.getSubject()).isEqualTo("user1");
		assertThat(jwt.getClaimAsString("email")).isEqualTo("user1@example.com");
		assertThat(jwt.getClaimAsString("name")).isEqualTo("User One");
	}

	@Test
	public void decodeWhenSignedWithHs256AndResolverConfiguredThenClientSecretIsUsed() throws Exception {
		this.factory.setJwsAlgorithmResolver((clientRegistration) -> MacAlgorithm.HS256);
		String token = signed(claims(), JWSAlgorithm.HS256, new MACSigner(CLIENT_SECRET.getBytes()));
		Jwt jwt = this.factory.createDecoder(this.registration.clientSecret(CLIENT_SECRET).build()).decode(token);
		assertThat(jwt.getSubject()).isEqualTo("user1");
	}

	@Test
	public void decodeWhenSignedWithEs256AndResolverConfiguredThenClaimsReturned() throws Exception {
		this.factory.setJwsAlgorithmResolver((clientRegistration) -> SignatureAlgorithm.ES256);
		String token = signed(claims(), JWSAlgorithm.ES256, new ECDSASigner(TestJwks.DEFAULT_EC_JWK));
		Jwt jwt = this.factory.createDecoder(this.registration.build()).decode(token);
		assertThat(jwt.getSubject()).isEqualTo("user1");
	}

	@Test
	public void decodeWhenSignedWithUnexpectedAlgorithmThenThrowJwtException() throws Exception {
		String token = signed(claims(), JWSAlgorithm.ES256, new ECDSASigner(TestJwks.DEFAULT_EC_JWK));
		JwtDecoder decoder = this.factory.createDecoder(this.registration.build());
		assertThatExceptionOfType(JwtException.class).isThrownBy(() -> decoder.decode(token));
	}

	@Test
	public void decodeWhenSignatureDoesNotMatchTheProviderKeysThenThrowJwtException() throws Exception {
		String token = signed(claims(), JWSAlgorithm.RS256, new RSASSASigner(this.encryptionRsaKey));
		JwtDecoder decoder = this.factory.createDecoder(this.registration.build());
		assertThatExceptionOfType(JwtException.class).isThrownBy(() -> decoder.decode(token));
	}

	@Test
	public void decodeWhenClaimsConfiguredThenStandardClaimsAreConverted() throws Exception {
		JWTClaimsSet.Builder claims = claims().claim("updated_at", 1700000000L).claim("email_verified", "true");
		Jwt jwt = this.factory.createDecoder(this.registration.build()).decode(signedByDefaultRsaKey(claims));
		assertThat(jwt.getClaims().get("updated_at")).isEqualTo(Instant.ofEpochSecond(1700000000L));
		assertThat(jwt.getClaims().get("email_verified")).isEqualTo(true);
	}

	@Test
	public void decodeWhenClaimTypeConverterFactoryConfiguredThenItIsUsed() throws Exception {
		this.factory.setClaimTypeConverterFactory((clientRegistration) -> (claims) -> {
			Map<String, Object> converted = new HashMap<>(claims);
			converted.put("converted-for", clientRegistration.getRegistrationId());
			return converted;
		});
		Jwt jwt = this.factory.createDecoder(this.registration.build()).decode(signedByDefaultRsaKey(claims()));
		assertThat(jwt.getClaims()).containsEntry("converted-for", "registration-id");
	}

	@Test
	public void decodeWhenIssuerAndAudienceAbsentThenAccepted() throws Exception {
		Jwt jwt = this.factory.createDecoder(this.registration.build()).decode(signedByDefaultRsaKey(claims()));
		assertThat(jwt.getIssuer()).isNull();
		assertThat(jwt.getAudience()).isNull();
	}

	@Test
	public void decodeWhenIssuerMatchesProviderIssuerThenAccepted() throws Exception {
		JWTClaimsSet.Builder claims = claims().issuer("https://example.com");
		Jwt jwt = this.factory.createDecoder(this.registration.build()).decode(signedByDefaultRsaKey(claims));
		assertThat(jwt.getIssuer()).hasToString("https://example.com");
	}

	@Test
	public void decodeWhenIssuerDoesNotMatchProviderIssuerThenThrowJwtValidationException() throws Exception {
		JWTClaimsSet.Builder claims = claims().issuer("https://attacker.example.org");
		JwtDecoder decoder = this.factory.createDecoder(this.registration.build());
		String token = signedByDefaultRsaKey(claims);
		assertThatExceptionOfType(JwtValidationException.class).isThrownBy(() -> decoder.decode(token))
			.withMessageContaining("iss");
	}

	@Test
	public void decodeWhenProviderIssuerNotConfiguredThenIssuerNotChecked() throws Exception {
		JWTClaimsSet.Builder claims = claims().issuer("https://any.example.org");
		Jwt jwt = this.factory.createDecoder(this.registration.issuerUri(null).build())
			.decode(signedByDefaultRsaKey(claims));
		assertThat(jwt.getIssuer()).hasToString("https://any.example.org");
	}

	@Test
	public void decodeWhenAudienceContainsClientIdThenAccepted() throws Exception {
		JWTClaimsSet.Builder claims = claims().audience(List.of("another-client", "client-id"));
		Jwt jwt = this.factory.createDecoder(this.registration.build()).decode(signedByDefaultRsaKey(claims));
		assertThat(jwt.getAudience()).containsExactly("another-client", "client-id");
	}

	@Test
	public void decodeWhenAudienceDoesNotContainClientIdThenThrowJwtValidationException() throws Exception {
		JWTClaimsSet.Builder claims = claims().audience("another-client");
		JwtDecoder decoder = this.factory.createDecoder(this.registration.build());
		String token = signedByDefaultRsaKey(claims);
		assertThatExceptionOfType(JwtValidationException.class).isThrownBy(() -> decoder.decode(token))
			.withMessageContaining("aud");
	}

	@Test
	public void decodeWhenExpiredThenThrowJwtValidationException() throws Exception {
		JWTClaimsSet.Builder claims = claims().expirationTime(Date.from(Instant.now().minusSeconds(7200)));
		JwtDecoder decoder = this.factory.createDecoder(this.registration.build());
		String token = signedByDefaultRsaKey(claims);
		assertThatExceptionOfType(JwtValidationException.class).isThrownBy(() -> decoder.decode(token));
	}

	@Test
	public void decodeWhenJwtValidatorFactoryConfiguredThenItIsUsed() throws Exception {
		OAuth2Error error = new OAuth2Error("custom_error", "rejected by the custom validator", null);
		this.factory.setJwtValidatorFactory((clientRegistration) -> (jwt) -> OAuth2TokenValidatorResult.failure(error));
		JwtDecoder decoder = this.factory.createDecoder(this.registration.build());
		String token = signedByDefaultRsaKey(claims());
		assertThatExceptionOfType(JwtValidationException.class).isThrownBy(() -> decoder.decode(token))
			.withMessageContaining("rejected by the custom validator");
	}

	@Test
	public void decodeWhenSignedThenEncryptedWithRsaThenClaimsAreDecryptedAndVerified() throws Exception {
		this.factory.setJweDecryptionKeyResolver((clientRegistration) -> this.encryptionRsaKey);
		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).contentType("JWT")
			.build();
		String token = encrypt(signedByDefaultRsaKey(claims()), header,
				new RSAEncrypter(this.encryptionRsaKey.toRSAPublicKey()));
		Jwt jwt = this.factory.createDecoder(this.registration.build()).decode(token);
		assertThat(jwt.getSubject()).isEqualTo("user1");
		assertThat(jwt.getClaimAsString("email")).isEqualTo("user1@example.com");
	}

	@Test
	public void decodeWhenSignedThenEncryptedWithEcdhThenClaimsAreDecryptedAndVerified() throws Exception {
		ECKey ecEncryptionKey = new ECKeyGenerator(Curve.P_256).keyID("ec-encryption-key").generate();
		this.factory.setJweDecryptionKeyResolver((clientRegistration) -> ecEncryptionKey);
		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES_A128KW, EncryptionMethod.A128CBC_HS256)
			.contentType("JWT")
			.build();
		String token = encrypt(signedByDefaultRsaKey(claims()), header,
				new ECDHEncrypter(ecEncryptionKey.toECPublicKey()));
		Jwt jwt = this.factory.createDecoder(this.registration.build()).decode(token);
		assertThat(jwt.getSubject()).isEqualTo("user1");
	}

	@Test
	public void decodeWhenSignedThenEncryptedWithSharedKeyThenClaimsAreDecryptedAndVerified() throws Exception {
		OctetSequenceKey sharedKey = new OctetSequenceKeyGenerator(256).keyID("shared-key").generate();
		this.factory.setJweDecryptionKeyResolver((clientRegistration) -> sharedKey);
		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM).contentType("JWT").build();
		String token = encrypt(signedByDefaultRsaKey(claims()), header, new DirectEncrypter(sharedKey));
		Jwt jwt = this.factory.createDecoder(this.registration.build()).decode(token);
		assertThat(jwt.getSubject()).isEqualTo("user1");
	}

	@Test
	public void decodeWhenSignedWithoutEncryptionAndKeyResolverConfiguredThenClaimsReturned() throws Exception {
		this.factory.setJweDecryptionKeyResolver((clientRegistration) -> this.encryptionRsaKey);
		Jwt jwt = this.factory.createDecoder(this.registration.build()).decode(signedByDefaultRsaKey(claims()));
		assertThat(jwt.getSubject()).isEqualTo("user1");
	}

	@Test
	public void decodeWhenEncryptedAndNoKeyResolverConfiguredThenThrowOAuth2AuthenticationException() throws Exception {
		String token = rsaEncrypted(signedByDefaultRsaKey(claims()));
		JwtDecoder decoder = this.factory.createDecoder(this.registration.build());
		assertThatExceptionOfType(OAuth2AuthenticationException.class).isThrownBy(() -> decoder.decode(token))
			.withMessageContaining("missing_decryption_key")
			.withMessageContaining("registration-id");
	}

	@Test
	public void decodeWhenEncryptedAndKeyResolverReturnsNullThenThrowOAuth2AuthenticationException() throws Exception {
		this.factory.setJweDecryptionKeyResolver((clientRegistration) -> null);
		String token = rsaEncrypted(signedByDefaultRsaKey(claims()));
		JwtDecoder decoder = this.factory.createDecoder(this.registration.build());
		assertThatExceptionOfType(OAuth2AuthenticationException.class).isThrownBy(() -> decoder.decode(token))
			.withMessageContaining("missing_decryption_key");
	}

	@Test
	public void decodeWhenDecryptionKeyHasNoPrivatePartThenThrowOAuth2AuthenticationException() throws Exception {
		this.factory.setJweDecryptionKeyResolver((clientRegistration) -> this.encryptionRsaKey.toPublicJWK());
		String token = rsaEncrypted(signedByDefaultRsaKey(claims()));
		JwtDecoder decoder = this.factory.createDecoder(this.registration.build());
		assertThatExceptionOfType(OAuth2AuthenticationException.class).isThrownBy(() -> decoder.decode(token))
			.withMessageContaining("missing_decryption_key")
			.withMessageContaining("private");
	}

	@Test
	public void decodeWhenEncryptedForAnotherKeyThenThrowBadJwtException() throws Exception {
		this.factory.setJweDecryptionKeyResolver((clientRegistration) -> TestJwks.generateRsa().build());
		String token = rsaEncrypted(signedByDefaultRsaKey(claims()));
		JwtDecoder decoder = this.factory.createDecoder(this.registration.build());
		assertThatExceptionOfType(BadJwtException.class).isThrownBy(() -> decoder.decode(token))
			.withMessageContaining("decrypt");
	}

	@Test
	public void decodeWhenEncryptedPayloadIsNotASignedJwtThenThrowBadJwtException() throws Exception {
		this.factory.setJweDecryptionKeyResolver((clientRegistration) -> this.encryptionRsaKey);
		JWEObject jwe = new JWEObject(
				new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).build(),
				new Payload(claims().build().toJSONObject()));
		jwe.encrypt(new RSAEncrypter(this.encryptionRsaKey.toRSAPublicKey()));
		JwtDecoder decoder = this.factory.createDecoder(this.registration.build());
		assertThatExceptionOfType(BadJwtException.class).isThrownBy(() -> decoder.decode(jwe.serialize()))
			.withMessageContaining("signed JWT");
	}

	@Test
	public void decodeWhenEncryptedPayloadHasInvalidSignatureThenThrowJwtException() throws Exception {
		this.factory.setJweDecryptionKeyResolver((clientRegistration) -> this.encryptionRsaKey);
		String forged = signed(claims(), JWSAlgorithm.RS256, new RSASSASigner(this.encryptionRsaKey));
		JwtDecoder decoder = this.factory.createDecoder(this.registration.build());
		String token = rsaEncrypted(forged);
		assertThatExceptionOfType(JwtException.class).isThrownBy(() -> decoder.decode(token));
	}

	@Test
	public void decodeWhenEncryptedPayloadIsExpiredThenThrowJwtValidationException() throws Exception {
		this.factory.setJweDecryptionKeyResolver((clientRegistration) -> this.encryptionRsaKey);
		JWTClaimsSet.Builder claims = claims().expirationTime(Date.from(Instant.now().minusSeconds(7200)));
		String token = rsaEncrypted(signedByDefaultRsaKey(claims));
		JwtDecoder decoder = this.factory.createDecoder(this.registration.build());
		assertThatExceptionOfType(JwtValidationException.class).isThrownBy(() -> decoder.decode(token));
	}

	@Test
	public void decodeWhenTokenIsMalformedThenThrowBadJwtException() {
		JwtDecoder decoder = this.factory.createDecoder(this.registration.build());
		assertThatExceptionOfType(BadJwtException.class).isThrownBy(() -> decoder.decode("not-a-jwt"));
	}

	private static JWTClaimsSet.Builder claims() {
		return new JWTClaimsSet.Builder().subject("user1")
			.claim("name", "User One")
			.claim("email", "user1@example.com");
	}

	private static String signedByDefaultRsaKey(JWTClaimsSet.Builder claims) throws JOSEException {
		return signed(claims, JWSAlgorithm.RS256, new RSASSASigner(TestKeys.DEFAULT_PRIVATE_KEY));
	}

	private static String signed(JWTClaimsSet.Builder claims, JWSAlgorithm algorithm, JWSSigner signer)
			throws JOSEException {
		SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(algorithm).build(), claims.build());
		jwt.sign(signer);
		return jwt.serialize();
	}

	private String rsaEncrypted(String signedJwt) throws Exception {
		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).contentType("JWT")
			.build();
		return encrypt(signedJwt, header, new RSAEncrypter(this.encryptionRsaKey.toRSAPublicKey()));
	}

	private static String encrypt(String signedJwt, JWEHeader header, JWEEncrypter encrypter) throws Exception {
		JWEObject jwe = new JWEObject(header, new Payload(SignedJWT.parse(signedJwt)));
		jwe.encrypt(encrypter);
		return jwe.serialize();
	}

}
