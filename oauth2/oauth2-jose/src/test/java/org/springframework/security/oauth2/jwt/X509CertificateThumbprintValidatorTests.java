/*
 * Copyright 2002-2024 the original author or authors.
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

import java.util.Collections;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jose.TestX509Certificates;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * @author Joe Grandja
 * @since 6.3
 */
class X509CertificateThumbprintValidatorTests {

	private final X509CertificateThumbprintValidator validator = new X509CertificateThumbprintValidator(
			X509CertificateThumbprintValidator.DEFAULT_X509_CERTIFICATE_SUPPLIER);

	@AfterEach
	void cleanup() {
		RequestContextHolder.resetRequestAttributes();
	}

	@Test
	void constructorWhenX509CertificateSupplierNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new X509CertificateThumbprintValidator(null)).withMessage("x509CertificateSupplier cannot be null");
		// @formatter:on
	}

	@Test
	void validateWhenCnfClaimNotAvailableThenSuccess() {
		Jwt jwt = TestJwts.jwt().build();
		assertThat(this.validator.validate(jwt).hasErrors()).isFalse();
	}

	@Test
	void validateWhenX5tClaimNotAvailableThenSuccess() {
		// @formatter:off
		Jwt jwt = TestJwts.jwt()
				.claim("cnf", Collections.emptyMap())
				.build();
		// @formatter:on
		assertThat(this.validator.validate(jwt).hasErrors()).isFalse();
	}

	@Test
	void validateWhenX509CertificateMissingThenHasErrors() throws Exception {
		String sha256Thumbprint = X509CertificateThumbprintValidator
			.computeSHA256Thumbprint(TestX509Certificates.DEFAULT_PKI_CERTIFICATE[0]);
		// @formatter:off
		Jwt jwt = TestJwts.jwt()
				.claim("cnf", Collections.singletonMap("x5t#S256", sha256Thumbprint))
				.build();
		// @formatter:on

		// @formatter:off
		assertThat(this.validator.validate(jwt).getErrors())
				.hasSize(1)
				.first()
				.satisfies((error) -> {
					assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
					assertThat(error.getDescription()).isEqualTo("Unable to obtain X509Certificate from current request.");
				});
		// @formatter:on
	}

	@Test
	void validateWhenX509CertificateThumbprintInvalidThenHasErrors() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setAttribute("jakarta.servlet.request.X509Certificate",
				TestX509Certificates.DEFAULT_SELF_SIGNED_CERTIFICATE);
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, null));

		String sha256Thumbprint = X509CertificateThumbprintValidator
			.computeSHA256Thumbprint(TestX509Certificates.DEFAULT_PKI_CERTIFICATE[0]);
		// @formatter:off
		Jwt jwt = TestJwts.jwt()
				.claim("cnf", Collections.singletonMap("x5t#S256", sha256Thumbprint))
				.build();
		// @formatter:on

		// @formatter:off
		assertThat(this.validator.validate(jwt).getErrors())
				.hasSize(1)
				.first()
				.satisfies((error) -> {
					assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
					assertThat(error.getDescription()).isEqualTo("Invalid SHA-256 Thumbprint for X509Certificate.");
				});
		// @formatter:on
	}

	@Test
	void validateWhenX509CertificateThumbprintValidThenSuccess() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setAttribute("jakarta.servlet.request.X509Certificate", TestX509Certificates.DEFAULT_PKI_CERTIFICATE);
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, null));

		String sha256Thumbprint = X509CertificateThumbprintValidator
			.computeSHA256Thumbprint(TestX509Certificates.DEFAULT_PKI_CERTIFICATE[0]);
		// @formatter:off
		Jwt jwt = TestJwts.jwt()
				.claim("cnf", Collections.singletonMap("x5t#S256", sha256Thumbprint))
				.build();
		// @formatter:on

		assertThat(this.validator.validate(jwt).hasErrors()).isFalse();
	}

}
