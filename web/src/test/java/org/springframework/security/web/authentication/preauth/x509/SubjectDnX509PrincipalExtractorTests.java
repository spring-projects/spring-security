/*
 * Copyright 2002-2016 the original author or authors.
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

import org.junit.Before;
import org.junit.Test;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.SpringSecurityMessageSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Luke Taylor
 */
public class SubjectDnX509PrincipalExtractorTests {

	SubjectDnX509PrincipalExtractor extractor;

	@Before
	public void setUp() {
		extractor = new SubjectDnX509PrincipalExtractor();
		extractor.setMessageSource(new SpringSecurityMessageSource());
	}

	@Test(expected = IllegalArgumentException.class)
	public void invalidRegexFails() {
		extractor.setSubjectDnRegex("CN=(.*?,"); // missing closing bracket on group
	}

	@Test
	public void defaultCNPatternReturnsExcpectedPrincipal() throws Exception {
		Object principal = extractor.extractPrincipal(X509TestUtils.buildTestCertificate());
		assertThat(principal).isEqualTo("Luke Taylor");
	}

	@Test
	public void matchOnEmailReturnsExpectedPrincipal() throws Exception {
		extractor.setSubjectDnRegex("emailAddress=(.*?),");
		Object principal = extractor.extractPrincipal(X509TestUtils.buildTestCertificate());
		assertThat(principal).isEqualTo("luke@monkeymachine");
	}

	@Test(expected = BadCredentialsException.class)
	public void matchOnShoeSizeThrowsBadCredentials() throws Exception {
		extractor.setSubjectDnRegex("shoeSize=(.*?),");
		extractor.extractPrincipal(X509TestUtils.buildTestCertificate());
	}

	@Test
	public void defaultCNPatternReturnsPrincipalAtEndOfDNString() throws Exception {
		Object principal = extractor.extractPrincipal(X509TestUtils.buildTestCertificateWithCnAtEnd());
		assertThat(principal).isEqualTo("Duke");
	}

}
