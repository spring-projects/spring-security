/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.web.csrf;

import org.assertj.core.api.AbstractAssert;
import org.assertj.core.api.Assertions;

/**
 * Assertion for validating the properties on CsrfToken are the same.
 */
public class CsrfTokenAssert extends AbstractAssert<CsrfTokenAssert, CsrfToken> {

	protected CsrfTokenAssert(CsrfToken csrfToken) {
		super(csrfToken, CsrfTokenAssert.class);
	}

	public static CsrfTokenAssert assertThatCsrfToken(Object csrfToken) {
		return new CsrfTokenAssert((CsrfToken) csrfToken);
	}

	public static CsrfTokenAssert assertThat(CsrfToken csrfToken) {
		return new CsrfTokenAssert(csrfToken);
	}

	public CsrfTokenAssert isEqualTo(CsrfToken csrfToken) {
		isNotNull();
		assertThat(csrfToken).isNotNull();
		Assertions.assertThat(this.actual.getHeaderName()).isEqualTo(csrfToken.getHeaderName());
		Assertions.assertThat(this.actual.getParameterName()).isEqualTo(csrfToken.getParameterName());
		Assertions.assertThat(this.actual.getToken()).isEqualTo(csrfToken.getToken());
		return this;
	}

}
