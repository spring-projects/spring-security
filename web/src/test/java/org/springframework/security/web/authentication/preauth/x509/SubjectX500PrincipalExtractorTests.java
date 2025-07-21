/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.web.authentication.preauth.x509;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link SubjectX500PrincipalExtractor}.
 *
 * @author Max Batischev
 */
public class SubjectX500PrincipalExtractorTests {

	private final SubjectX500PrincipalExtractor extractor = new SubjectX500PrincipalExtractor();

	@Test
	void extractWhenCnPatternSetThenExtractsPrincipalName() throws Exception {
		Object principal = this.extractor.extractPrincipal(X509TestUtils.buildTestCertificate());

		assertThat(principal).isEqualTo("Luke Taylor");
	}

	@Test
	void extractWhenEmailPatternSetThenExtractsPrincipalName() throws Exception {
		this.extractor.setExtractPrincipalNameFromEmail(true);

		Object principal = this.extractor.extractPrincipal(X509TestUtils.buildTestCertificate());

		assertThat(principal).isEqualTo("luke@monkeymachine");
	}

	@Test
	void extractWhenCnAtEndThenExtractsPrincipalName() throws Exception {
		Object principal = this.extractor.extractPrincipal(X509TestUtils.buildTestCertificateWithCnAtEnd());

		assertThat(principal).isEqualTo("Duke");
	}

	@Test
	void setMessageSourceWhenNullThenThrowsException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.extractor.setMessageSource(null));
	}

	@Test
	void extractWhenCertificateIsNullThenFails() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.extractor.extractPrincipal(null));
	}

}
