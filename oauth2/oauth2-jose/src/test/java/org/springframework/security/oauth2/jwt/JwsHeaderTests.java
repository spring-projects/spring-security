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

package org.springframework.security.oauth2.jwt;

import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link JwsHeader}.
 *
 * @author Joe Grandja
 */
public class JwsHeaderTests {

	@Test
	public void withWhenNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> JwsHeader.with(null))
				.withMessage("jwsAlgorithm cannot be null");
	}

	@Test
	public void fromWhenNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> JwsHeader.from(null))
				.withMessage("headers cannot be null");
	}

	@Test
	public void fromWhenHeadersProvidedThenCopied() {
		JwsHeader expectedJwsHeader = TestJwsHeaders.jwsHeader().build();
		JwsHeader jwsHeader = JwsHeader.from(expectedJwsHeader).build();
		assertThat(jwsHeader.getHeaders()).isEqualTo(expectedJwsHeader.getHeaders());
	}

	@Test
	public void buildWhenAllHeadersProvidedThenAllHeadersAreSet() {
		JwsHeader expectedJwsHeader = TestJwsHeaders.jwsHeader().build();

		// @formatter:off
		JwsHeader jwsHeader = JwsHeader.with(expectedJwsHeader.getAlgorithm())
				.jwkSetUrl(expectedJwsHeader.getJwkSetUrl().toExternalForm())
				.jwk(expectedJwsHeader.getJwk())
				.keyId(expectedJwsHeader.getKeyId())
				.x509Url(expectedJwsHeader.getX509Url().toExternalForm())
				.x509CertificateChain(expectedJwsHeader.getX509CertificateChain())
				.x509SHA1Thumbprint(expectedJwsHeader.getX509SHA1Thumbprint())
				.x509SHA256Thumbprint(expectedJwsHeader.getX509SHA256Thumbprint())
				.type(expectedJwsHeader.getType())
				.contentType(expectedJwsHeader.getContentType())
				.criticalHeader("critical-header1-name", "critical-header1-value")
				.criticalHeader("critical-header2-name", "critical-header2-value")
				.headers((headers) -> headers.put("custom-header-name", "custom-header-value"))
				.build();
		// @formatter:on

		assertThat(jwsHeader.getAlgorithm()).isEqualTo(expectedJwsHeader.getAlgorithm());
		assertThat(jwsHeader.getJwkSetUrl()).isEqualTo(expectedJwsHeader.getJwkSetUrl());
		assertThat(jwsHeader.getJwk()).isEqualTo(expectedJwsHeader.getJwk());
		assertThat(jwsHeader.getKeyId()).isEqualTo(expectedJwsHeader.getKeyId());
		assertThat(jwsHeader.getX509Url()).isEqualTo(expectedJwsHeader.getX509Url());
		assertThat(jwsHeader.getX509CertificateChain()).isEqualTo(expectedJwsHeader.getX509CertificateChain());
		assertThat(jwsHeader.getX509SHA1Thumbprint()).isEqualTo(expectedJwsHeader.getX509SHA1Thumbprint());
		assertThat(jwsHeader.getX509SHA256Thumbprint()).isEqualTo(expectedJwsHeader.getX509SHA256Thumbprint());
		assertThat(jwsHeader.getType()).isEqualTo(expectedJwsHeader.getType());
		assertThat(jwsHeader.getContentType()).isEqualTo(expectedJwsHeader.getContentType());
		assertThat(jwsHeader.getCritical()).containsExactlyInAnyOrder("critical-header1-name", "critical-header2-name");
		assertThat(jwsHeader.<String>getHeader("critical-header1-name")).isEqualTo("critical-header1-value");
		assertThat(jwsHeader.<String>getHeader("critical-header2-name")).isEqualTo("critical-header2-value");
		assertThat(jwsHeader.<String>getHeader("custom-header-name")).isEqualTo("custom-header-value");
	}

	@Test
	public void headerWhenNameNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> JwsHeader.with(SignatureAlgorithm.RS256).header(null, "value"))
				.withMessage("name cannot be empty");
	}

	@Test
	public void headerWhenValueNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> JwsHeader.with(SignatureAlgorithm.RS256).header("name", null))
				.withMessage("value cannot be null");
	}

	@Test
	public void getHeaderWhenNullThenThrowIllegalArgumentException() {
		JwsHeader jwsHeader = TestJwsHeaders.jwsHeader().build();

		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> jwsHeader.getHeader(null))
				.withMessage("name cannot be empty");
	}

}
