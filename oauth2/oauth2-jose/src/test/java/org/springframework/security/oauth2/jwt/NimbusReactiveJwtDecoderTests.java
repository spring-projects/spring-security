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

package org.springframework.security.oauth2.jwt;

import java.net.UnknownHostException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import javax.crypto.SecretKey;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWKSecurityContext;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.assertj.core.api.AssertionsForClassTypes;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.TestKeys;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.web.reactive.function.client.WebClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder.withJwkSetUri;
import static org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder.withJwkSource;
import static org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder.withPublicKey;
import static org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder.withSecretKey;

/**
 * @author Rob Winch
 * @author Joe Grandja
 * @since 5.1
 */
public class NimbusReactiveJwtDecoderTests {

	private String expired = "eyJraWQiOiJrZXktaWQtMSIsImFsZyI6IlJTMjU2In0.eyJzY29wZSI6Im1lc3NhZ2U6cmVhZCIsImV4cCI6MTUyOTkzNzYzMX0.Dt5jFOKkB8zAmjciwvlGkj4LNStXWH0HNIfr8YYajIthBIpVgY5Hg_JL8GBmUFzKDgyusT0q60OOg8_Pdi4Lu-VTWyYutLSlNUNayMlyBaVEWfyZJnh2_OwMZr1vRys6HF-o1qZldhwcfvczHg61LwPa1ISoqaAltDTzBu9cGISz2iBUCuR0x71QhbuRNyJdjsyS96NqiM_TspyiOSxmlNch2oAef1MssOQ23CrKilIvEDsz_zk5H94q7rH0giWGdEHCENESsTJS0zvzH6r2xIWjd5WnihFpCPkwznEayxaEhrdvJqT_ceyXCIfY4m3vujPQHNDG0UshpwvDuEbPUg";
	private String messageReadToken = "eyJraWQiOiJrZXktaWQtMSIsImFsZyI6IlJTMjU2In0.eyJzY29wZSI6Im1lc3NhZ2U6cmVhZCIsImV4cCI6OTIyMzM3MjAwNjA5NjM3NX0.bnQ8IJDXmQbmIXWku0YT1HOyV_3d0iQSA_0W2CmPyELhsxFETzBEEcZ0v0xCBiswDT51rwD83wbX3YXxb84fM64AhpU8wWOxLjha4J6HJX2JnlG47ydaAVD7eWGSYTavyyQ-CwUjQWrfMVcObFZLYG11ydzRYOR9-aiHcK3AobcTcS8jZFeI8EGQV_Cd3IJ018uFCf6VnXLv7eV2kRt08Go2RiPLW47ExvD7Dzzz_wDBKfb4pNem7fDvuzB3UPcp5m9QvLZicnbS_6AvDi6P1y_DFJf-1T5gkGmX5piDH1L1jg2Yl6tjmXbk5B3VhsyjJuXE6gzq1d-xie0Z1NVOxw";
	private String unsignedToken = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJleHAiOi0yMDMzMjI0OTcsImp0aSI6IjEyMyIsInR5cCI6IkpXVCJ9.";
	private String jwkSet =
		"{\n"
		+ "   \"keys\":[\n"
		+ "      {\n"
		+ "         \"kty\":\"RSA\",\n"
		+ "         \"e\":\"AQAB\",\n"
		+ "         \"use\":\"sig\",\n"
		+ "         \"kid\":\"key-id-1\",\n"
		+ "         \"n\":\"qL48v1clgFw-Evm145pmh8nRYiNt72Gupsshn7Qs8dxEydCRp1DPOV_PahPk1y2nvldBNIhfNL13JOAiJ6BTiF-2ICuICAhDArLMnTH61oL1Hepq8W1xpa9gxsnL1P51thvfmiiT4RTW57koy4xIWmIp8ZXXfYgdH2uHJ9R0CQBuYKe7nEOObjxCFWC8S30huOfW2cYtv0iB23h6w5z2fDLjddX6v_FXM7ktcokgpm3_XmvT_-bL6_GGwz9k6kJOyMTubecr-WT__le8ikY66zlplYXRQh6roFfFCL21Pt8xN5zrk-0AMZUnmi8F2S2ztSBmAVJ7H71ELXsURBVZpw\"\n"
		+ "      }\n"
		+ "   ]\n"
		+ "}";
	private String jwkSetUri = "https://issuer/certs";

	private String rsa512 = "eyJhbGciOiJSUzUxMiJ9.eyJzdWIiOiJ0ZXN0LXN1YmplY3QiLCJleHAiOjE5NzQzMjYxMTl9.LKAx-60EBfD7jC1jb1eKcjO4uLvf3ssISV-8tN-qp7gAjSvKvj4YA9-V2mIb6jcS1X_xGmNy6EIimZXpWaBR3nJmeu-jpe85u4WaW2Ztr8ecAi-dTO7ZozwdtljKuBKKvj4u1nF70zyCNl15AozSG0W1ASrjUuWrJtfyDG6WoZ8VfNMuhtU-xUYUFvscmeZKUYQcJ1KS-oV5tHeF8aNiwQoiPC_9KXCOZtNEJFdq6-uzFdHxvOP2yex5Gbmg5hXonauIFXG2ZPPGdXzm-5xkhBpgM8U7A_6wb3So8wBvLYYm2245QUump63AJRAy8tQpwt4n9MvQxQgS3z9R-NK92A";
	private String rsa256 = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0LXN1YmplY3QiLCJleHAiOjE5NzQzMjYzMzl9.CT-H2OWEqmSs1NWmnta5ealLFvM8OlbQTjGhfRcKLNxrTrzsOkqBJl-AN3k16BQU7mS32o744TiiZ29NcDlxPsr1MqTlN86-dobPiuNIDLp3A1bOVdXMcVFuMYkrNv0yW0tGS9OjEqsCCuZDkZ1by6AhsHLbGwRY-6AQdcRouZygGpOQu1hNun5j8q5DpSTY4AXKARIFlF-O3OpVbPJ0ebr3Ki-i3U9p_55H0e4-wx2bqcApWlqgofl1I8NKWacbhZgn81iibup2W7E0CzCzh71u1Mcy3xk1sYePx-dwcxJnHmxJReBBWjJZEAeCrkbnn_OCuo2fA-EQyNJtlN5F2w";
	private String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq4yKxb6SNePdDmQi9xFCrP6QvHosErQzryknQTTTffs0t3cy3Er3lIceuhZ7yQNSCDfPFqG8GoyoKhuChRiA5D+J2ab7bqTa1QJKfnCyERoscftgN2fXPHjHoiKbpGV2tMVw8mXl//tePOAiKbMJaBUnlAvJgkk1rVm08dSwpLC1sr2M19euf9jwnRGkMRZuhp9iCPgECRke5T8Ixpv0uQjSmGHnWUKTFlbj8sM83suROR1Ue64JSGScANc5vk3huJ/J97qTC+K2oKj6L8d9O8dpc4obijEOJwpydNvTYDgbiivYeSB00KS9jlBkQ5B2QqLvLVEygDl3dp59nGx6YQIDAQAB";

	private MockWebServer server;
	private NimbusReactiveJwtDecoder decoder;

	private static KeyFactory kf;

	@BeforeClass
	public static void keyFactory() throws NoSuchAlgorithmException {
		kf = KeyFactory.getInstance("RSA");
	}

	@Before
	public void setup() throws Exception {
		this.server = new MockWebServer();
		this.server.start();
		this.server.enqueue(new MockResponse().setBody(jwkSet));
		this.decoder = new NimbusReactiveJwtDecoder(this.server.url("/certs").toString());
	}

	@After
	public void cleanup() throws Exception {
		this.server.shutdown();
	}

	@Test
	public void decodeWhenInvalidUrl() {
		this.decoder = new NimbusReactiveJwtDecoder("https://s");

		assertThatCode(() -> this.decoder.decode(this.messageReadToken).block())
			.isInstanceOf(IllegalStateException.class)
			.hasCauseInstanceOf(UnknownHostException.class);

	}

	@Test
	public void decodeWhenMessageReadScopeThenSuccess() {
		Jwt jwt = this.decoder.decode(this.messageReadToken).block();

		assertThat(jwt.getClaims().get("scope")).isEqualTo("message:read");
	}

	@Test
	public void decodeWhenRSAPublicKeyThenSuccess() throws Exception {
		byte[] bytes = Base64.getDecoder().decode("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqL48v1clgFw+Evm145pmh8nRYiNt72Gupsshn7Qs8dxEydCRp1DPOV/PahPk1y2nvldBNIhfNL13JOAiJ6BTiF+2ICuICAhDArLMnTH61oL1Hepq8W1xpa9gxsnL1P51thvfmiiT4RTW57koy4xIWmIp8ZXXfYgdH2uHJ9R0CQBuYKe7nEOObjxCFWC8S30huOfW2cYtv0iB23h6w5z2fDLjddX6v/FXM7ktcokgpm3/XmvT/+bL6/GGwz9k6kJOyMTubecr+WT//le8ikY66zlplYXRQh6roFfFCL21Pt8xN5zrk+0AMZUnmi8F2S2ztSBmAVJ7H71ELXsURBVZpwIDAQAB");
		RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA")
				.generatePublic(new X509EncodedKeySpec(bytes));
		this.decoder = new NimbusReactiveJwtDecoder(publicKey);
		String noKeyId = "eyJhbGciOiJSUzI1NiJ9.eyJzY29wZSI6IiIsImV4cCI6OTIyMzM3MjAwNjA5NjM3NX0.hNVuHSUkxdLZrDfqdmKcOi0ggmNaDuB4ZPxPtJl1gwBiXzIGN6Hwl24O2BfBZiHFKUTQDs4_RvzD71mEG3DvUrcKmdYWqIB1l8KNmxQLUDG-cAPIpJmRJgCh50tf8OhOE_Cb9E1HcsOUb47kT9iz-VayNBcmo6BmyZLdEGhsdGBrc3Mkz2dd_0PF38I2Hf_cuSjn9gBjFGtiPEXJvob3PEjVTSx_zvodT8D9p3An1R3YBZf5JSd1cQisrXgDX2k1Jmf7UKKWzgfyCgnEtRWWbsUdPqo3rSEY9GDC1iSQXsFTTC1FT_JJDkwzGf011fsU5O_Ko28TARibmKTCxAKNRQ";

		assertThatCode(() -> this.decoder.decode(noKeyId).block())
			.doesNotThrowAnyException();
	}

	@Test
	public void decodeWhenIssuedAtThenSuccess() {
		String withIssuedAt = "eyJraWQiOiJrZXktaWQtMSIsImFsZyI6IlJTMjU2In0.eyJzY29wZSI6IiIsImV4cCI6OTIyMzM3MjAwNjA5NjM3NSwiaWF0IjoxNTI5OTQyNDQ4fQ.LBzAJO-FR-uJDHST61oX4kimuQjz6QMJPW_mvEXRB6A-fMQWpfTQ089eboipAqsb33XnwWth9ELju9HMWLk0FjlWVVzwObh9FcoKelmPNR8mZIlFG-pAYGgSwi8HufyLabXHntFavBiFtqwp_z9clSOFK1RxWvt3lywEbGgtCKve0BXOjfKWiH1qe4QKGixH-NFxidvz8Qd5WbJwyb9tChC6ZKoKPv7Jp-N5KpxkY-O2iUtINvn4xOSactUsvKHgF8ZzZjvJGzG57r606OZXaNtoElQzjAPU5xDGg5liuEJzfBhvqiWCLRmSuZ33qwp3aoBnFgEw0B85gsNe3ggABg";

		Jwt jwt = this.decoder.decode(withIssuedAt).block();

		assertThat(jwt.getClaims().get(JwtClaimNames.IAT)).isEqualTo(Instant.ofEpochSecond(1529942448L));
	}

	@Test
	public void decodeWhenExpiredThenFail() {
		assertThatCode(() -> this.decoder.decode(this.expired).block())
				.isInstanceOf(JwtValidationException.class);
	}

	@Test
	public void decodeWhenNoPeriodThenFail() {
		assertThatCode(() -> this.decoder.decode("").block())
				.isInstanceOf(BadJwtException.class);
	}

	@Test
	public void decodeWhenInvalidJwkSetUrlThenFail() {
		this.decoder = new NimbusReactiveJwtDecoder("http://localhost:1280/certs");
		assertThatCode(() -> this.decoder.decode(this.messageReadToken).block())
				.isInstanceOf(IllegalStateException.class);
	}

	@Test
	public void decodeWhenInvalidSignatureThenFail() {
		assertThatCode(() -> this.decoder.decode(this.messageReadToken.substring(0, this.messageReadToken.length() - 2)).block())
				.isInstanceOf(BadJwtException.class);
	}

	@Test
	public void decodeWhenAlgNoneThenFail() {
		assertThatCode(() -> this.decoder.decode("ew0KICAiYWxnIjogIm5vbmUiLA0KICAidHlwIjogIkpXVCINCn0.ew0KICAic3ViIjogIjEyMzQ1Njc4OTAiLA0KICAibmFtZSI6ICJKb2huIERvZSIsDQogICJpYXQiOiAxNTE2MjM5MDIyDQp9.").block())
			.isInstanceOf(BadJwtException.class)
			.hasMessage("Unsupported algorithm of none");
	}

	@Test
	public void decodeWhenInvalidAlgMismatchThenFail() {
		assertThatCode(() -> this.decoder.decode("ew0KICAiYWxnIjogIkVTMjU2IiwNCiAgInR5cCI6ICJKV1QiDQp9.ew0KICAic3ViIjogIjEyMzQ1Njc4OTAiLA0KICAibmFtZSI6ICJKb2huIERvZSIsDQogICJpYXQiOiAxNTE2MjM5MDIyDQp9.").block())
				.isInstanceOf(BadJwtException.class);
	}

	@Test
	public void decodeWhenUnsignedTokenThenMessageDoesNotMentionClass() {
		assertThatCode(() -> this.decoder.decode(this.unsignedToken).block())
				.isInstanceOf(BadJwtException.class)
				.hasMessage("Unsupported algorithm of none");
	}

	@Test
	public void decodeWhenUsingCustomValidatorThenValidatorIsInvoked() {
		OAuth2TokenValidator jwtValidator = mock(OAuth2TokenValidator.class);
		this.decoder.setJwtValidator(jwtValidator);

		OAuth2Error error = new OAuth2Error("mock-error", "mock-description", "mock-uri");
		OAuth2TokenValidatorResult result = OAuth2TokenValidatorResult.failure(error);
		when(jwtValidator.validate(any(Jwt.class))).thenReturn(result);

		assertThatCode(() -> this.decoder.decode(this.messageReadToken).block())
				.isInstanceOf(JwtValidationException.class)
				.hasMessageContaining("mock-description");
	}

	@Test
	public void decodeWhenUsingSignedJwtThenReturnsClaimsGivenByClaimSetConverter() {
		Converter<Map<String, Object>, Map<String, Object>> claimSetConverter = mock(Converter.class);
		this.decoder.setClaimSetConverter(claimSetConverter);

		when(claimSetConverter.convert(any(Map.class))).thenReturn(Collections.singletonMap("custom", "value"));

		Jwt jwt = this.decoder.decode(this.messageReadToken).block();
		assertThat(jwt.getClaims().size()).isEqualTo(1);
		assertThat(jwt.getClaims().get("custom")).isEqualTo("value");
		verify(claimSetConverter).convert(any(Map.class));
	}

	// gh-7885
	@Test
	public void decodeWhenClaimSetConverterFailsThenBadJwtException() {
		Converter<Map<String, Object>, Map<String, Object>> claimSetConverter = mock(Converter.class);
		this.decoder.setClaimSetConverter(claimSetConverter);

		when(claimSetConverter.convert(any(Map.class))).thenThrow(new IllegalArgumentException("bad conversion"));

		assertThatCode(() -> this.decoder.decode(this.messageReadToken).block())
				.isInstanceOf(BadJwtException.class);
	}

	@Test
	public void setJwtValidatorWhenGivenNullThrowsIllegalArgumentException() {
		assertThatCode(() -> this.decoder.setJwtValidator(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void setClaimSetConverterWhenNullThrowsIllegalArgumentException() {
		assertThatCode(() -> this.decoder.setClaimSetConverter(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void withJwkSetUriWhenNullOrEmptyThenThrowsException() {
		assertThatCode(() -> withJwkSetUri(null)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void jwsAlgorithmWhenNullThenThrowsException() {
		NimbusReactiveJwtDecoder.JwkSetUriReactiveJwtDecoderBuilder builder = withJwkSetUri(this.jwkSetUri);
		assertThatCode(() -> builder.jwsAlgorithm(null)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void withJwkSetUriWhenJwtProcessorCustomizerNullThenThrowsIllegalArgumentException() {
		assertThatCode(() -> withJwkSetUri(jwkSetUri).jwtProcessorCustomizer(null).build())
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("jwtProcessorCustomizer cannot be null");
	}

	@Test
	public void restOperationsWhenNullThenThrowsException() {
		NimbusReactiveJwtDecoder.JwkSetUriReactiveJwtDecoderBuilder builder = withJwkSetUri(this.jwkSetUri);
		assertThatCode(() -> builder.webClient(null)).isInstanceOf(IllegalArgumentException.class);
	}

	// gh-5603
	@Test
	public void decodeWhenSignedThenOk() {
		WebClient webClient = mockJwkSetResponse(this.jwkSet);
		NimbusReactiveJwtDecoder decoder = withJwkSetUri(this.jwkSetUri).webClient(webClient).build();
		assertThat(decoder.decode(messageReadToken).block())
				.extracting(Jwt::getExpiresAt)
				.isNotNull();
		verify(webClient).get();
	}

	// gh-8730
	@Test
	public void withJwkSetUriWhenUsingCustomTypeHeaderThenRefuseOmittedType() {
		WebClient webClient = mockJwkSetResponse(this.jwkSet);
		NimbusReactiveJwtDecoder decoder = withJwkSetUri(this.jwkSetUri)
				.webClient(webClient)
				.jwtProcessorCustomizer(p -> p.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("JWS"))))
				.build();
		assertThatCode(() -> decoder.decode(messageReadToken).block())
				.isInstanceOf(BadJwtException.class)
				.hasRootCauseMessage("Required JOSE header \"typ\" (type) parameter is missing");
	}

	@Test
	public void withPublicKeyWhenNullThenThrowsException() {
		assertThatThrownBy(() -> withPublicKey(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void buildWhenSignatureAlgorithmMismatchesKeyTypeThenThrowsException() {
		assertThatCode(() -> withPublicKey(key())
				.signatureAlgorithm(SignatureAlgorithm.ES256)
				.build())
				.isInstanceOf(IllegalStateException.class);
	}

	@Test
	public void buildWhenJwtProcessorCustomizerNullThenThrowsIllegalArgumentException() {
		assertThatCode(() -> withPublicKey(key()).jwtProcessorCustomizer(null).build())
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("jwtProcessorCustomizer cannot be null");
	}

	@Test
	public void decodeWhenUsingPublicKeyThenSuccessfullyDecodes() throws Exception {
		NimbusReactiveJwtDecoder decoder = withPublicKey(key()).build();
		assertThat(decoder.decode(this.rsa256).block())
				.extracting(Jwt::getSubject)
				.isEqualTo("test-subject");
	}

	@Test
	public void decodeWhenUsingPublicKeyWithRs512ThenSuccessfullyDecodes() throws Exception {
		NimbusReactiveJwtDecoder decoder =
				withPublicKey(key()).signatureAlgorithm(SignatureAlgorithm.RS512).build();
		assertThat(decoder.decode(this.rsa512).block())
				.extracting(Jwt::getSubject)
				.isEqualTo("test-subject");
	}

	@Test
	public void decodeWhenSignatureMismatchesAlgorithmThenThrowsException() throws Exception {
		NimbusReactiveJwtDecoder decoder =
				withPublicKey(key()).signatureAlgorithm(SignatureAlgorithm.RS512).build();
		assertThatCode(() -> decoder.decode(this.rsa256).block())
				.isInstanceOf(BadJwtException.class);
	}

	// gh-8730
	@Test
	public void withPublicKeyWhenUsingCustomTypeHeaderThenRefuseOmittedType() throws Exception {
		NimbusReactiveJwtDecoder decoder = withPublicKey(key())
				.jwtProcessorCustomizer(p -> p.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("JWS"))))
				.build();

		AssertionsForClassTypes.assertThatCode(() -> decoder.decode(this.rsa256).block())
				.isInstanceOf(BadJwtException.class)
				.hasRootCauseMessage("Required JOSE header \"typ\" (type) parameter is missing");
	}

	@Test
	public void withJwkSourceWhenNullThenThrowsException() {
		assertThatCode(() -> withJwkSource(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void withJwkSourceWhenJwtProcessorCustomizerNullThenThrowsIllegalArgumentException() {
		assertThatCode(() -> withJwkSource(jwt -> Flux.empty()).jwtProcessorCustomizer(null).build())
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("jwtProcessorCustomizer cannot be null");
	}

	@Test
	public void decodeWhenCustomJwkSourceResolutionThenDecodes() {
		NimbusReactiveJwtDecoder decoder =
				withJwkSource(jwt -> Flux.fromIterable(parseJWKSet(this.jwkSet).getKeys()))
						.build();

		assertThat(decoder.decode(this.messageReadToken).block())
				.extracting(Jwt::getExpiresAt)
				.isNotNull();
	}

	// gh-8730
	@Test
	public void withJwkSourceWhenUsingCustomTypeHeaderThenRefuseOmittedType() {
		NimbusReactiveJwtDecoder decoder = withJwkSource(jwt -> Flux.empty())
				.jwtProcessorCustomizer(p -> p.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("JWS"))))
				.build();

		assertThatCode(() -> decoder.decode(this.messageReadToken).block())
				.isInstanceOf(BadJwtException.class)
				.hasRootCauseMessage("Required JOSE header \"typ\" (type) parameter is missing");
	}

	@Test
	public void withSecretKeyWhenSecretKeyNullThenThrowsIllegalArgumentException() {
		assertThatThrownBy(() -> withSecretKey(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("secretKey cannot be null");
	}

	@Test
	public void withSecretKeyWhenJwtProcessorCustomizerNullThenThrowsIllegalArgumentException() {
		SecretKey secretKey = TestKeys.DEFAULT_SECRET_KEY;
		assertThatThrownBy(() -> withSecretKey(secretKey).jwtProcessorCustomizer(null).build())
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("jwtProcessorCustomizer cannot be null");
	}

	@Test
	public void withSecretKeyWhenMacAlgorithmNullThenThrowsIllegalArgumentException() {
		SecretKey secretKey = TestKeys.DEFAULT_SECRET_KEY;
		assertThatThrownBy(() -> withSecretKey(secretKey).macAlgorithm(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("macAlgorithm cannot be null");
	}

	@Test
	public void decodeWhenSecretKeyThenSuccess() throws Exception {
		SecretKey secretKey = TestKeys.DEFAULT_SECRET_KEY;
		MacAlgorithm macAlgorithm = MacAlgorithm.HS256;
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
				.subject("test-subject")
				.expirationTime(Date.from(Instant.now().plusSeconds(60)))
				.build();
		SignedJWT signedJWT = signedJwt(secretKey, macAlgorithm, claimsSet);

		this.decoder = withSecretKey(secretKey).macAlgorithm(macAlgorithm).build();
		Jwt jwt = this.decoder.decode(signedJWT.serialize()).block();
		assertThat(jwt.getSubject()).isEqualTo("test-subject");
	}

	// gh-8730
	@Test
	public void withSecretKeyWhenUsingCustomTypeHeaderThenRefuseOmittedType() {
		SecretKey secretKey = TestKeys.DEFAULT_SECRET_KEY;
		NimbusReactiveJwtDecoder decoder = withSecretKey(secretKey)
				.jwtProcessorCustomizer(p -> p.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("JWS"))))
				.build();
		assertThatCode(() -> decoder.decode(messageReadToken).block())
				.isInstanceOf(BadJwtException.class)
				.hasRootCauseMessage("Required JOSE header \"typ\" (type) parameter is missing");
	}

	@Test
	public void decodeWhenSecretKeyAndAlgorithmMismatchThenThrowsJwtException() throws Exception {
		SecretKey secretKey = TestKeys.DEFAULT_SECRET_KEY;
		MacAlgorithm macAlgorithm = MacAlgorithm.HS256;
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
				.subject("test-subject")
				.expirationTime(Date.from(Instant.now().plusSeconds(60)))
				.build();
		SignedJWT signedJWT = signedJwt(secretKey, macAlgorithm, claimsSet);

		this.decoder = withSecretKey(secretKey).macAlgorithm(MacAlgorithm.HS512).build();
		assertThatThrownBy(() -> this.decoder.decode(signedJWT.serialize()).block())
				.isInstanceOf(BadJwtException.class);
	}

	@Test
	public void jwsKeySelectorWhenNoAlgorithmThenReturnsRS256Selector() {
		JWKSource<JWKSecurityContext> jwkSource = mock(JWKSource.class);
		JWSKeySelector<JWKSecurityContext> jwsKeySelector =
				withJwkSetUri(this.jwkSetUri).jwsKeySelector(jwkSource);
		assertThat(jwsKeySelector instanceof JWSVerificationKeySelector);
		JWSVerificationKeySelector<JWKSecurityContext> jwsVerificationKeySelector =
				(JWSVerificationKeySelector<JWKSecurityContext>) jwsKeySelector;
		assertThat(jwsVerificationKeySelector.isAllowed(JWSAlgorithm.RS256))
				.isTrue();
	}

	@Test
	public void jwsKeySelectorWhenOneAlgorithmThenReturnsSingleSelector() {
		JWKSource<JWKSecurityContext> jwkSource = mock(JWKSource.class);
		JWSKeySelector<JWKSecurityContext> jwsKeySelector =
				withJwkSetUri(this.jwkSetUri).jwsAlgorithm(SignatureAlgorithm.RS512)
						.jwsKeySelector(jwkSource);
		assertThat(jwsKeySelector instanceof JWSVerificationKeySelector);
		JWSVerificationKeySelector<JWKSecurityContext> jwsVerificationKeySelector =
				(JWSVerificationKeySelector<JWKSecurityContext>) jwsKeySelector;
		assertThat(jwsVerificationKeySelector.isAllowed(JWSAlgorithm.RS512))
				.isTrue();
	}

	@Test
	public void jwsKeySelectorWhenMultipleAlgorithmThenReturnsCompositeSelector() {
		JWKSource<JWKSecurityContext> jwkSource = mock(JWKSource.class);
		JWSKeySelector<JWKSecurityContext> jwsKeySelector =
				withJwkSetUri(this.jwkSetUri)
						.jwsAlgorithm(SignatureAlgorithm.RS256)
						.jwsAlgorithm(SignatureAlgorithm.RS512)
						.jwsKeySelector(jwkSource);
		assertThat(jwsKeySelector instanceof JWSVerificationKeySelector);
		JWSVerificationKeySelector<?> jwsAlgorithmMapKeySelector =
				(JWSVerificationKeySelector<?>) jwsKeySelector;
		assertThat(jwsAlgorithmMapKeySelector.isAllowed(JWSAlgorithm.RS256))
				.isTrue();
		assertThat(jwsAlgorithmMapKeySelector.isAllowed(JWSAlgorithm.RS512))
				.isTrue();
	}

	private SignedJWT signedJwt(SecretKey secretKey, MacAlgorithm jwsAlgorithm, JWTClaimsSet claimsSet) throws Exception {
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.parse(jwsAlgorithm.getName())), claimsSet);
		JWSSigner signer = new MACSigner(secretKey);
		signedJWT.sign(signer);
		return signedJWT;
	}

	private JWKSet parseJWKSet(String jwkSet) {
		try {
			return JWKSet.parse(jwkSet);
		} catch (ParseException e) {
			throw new IllegalArgumentException(e);
		}
	}

	private RSAPublicKey key() throws InvalidKeySpecException {
		byte[] decoded = Base64.getDecoder().decode(this.publicKey.getBytes());
		EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
		return (RSAPublicKey) kf.generatePublic(spec);
	}

	private static WebClient mockJwkSetResponse(String response) {
		WebClient real = WebClient.builder().build();
		WebClient.RequestHeadersUriSpec spec = spy(real.get());
		WebClient webClient = spy(WebClient.class);
		when(webClient.get()).thenReturn(spec);
		WebClient.ResponseSpec responseSpec = mock(WebClient.ResponseSpec.class);
		when(responseSpec.bodyToMono(String.class)).thenReturn(Mono.just(response));
		when(spec.retrieve()).thenReturn(responseSpec);
		return webClient;
	}
}
