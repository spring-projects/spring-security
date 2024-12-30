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

package org.springframework.security.web.webauthn.authentication;

import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.api.TestPublicKeyCredentialRequestOptions;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link HttpSessionPublicKeyCredentialRequestOptionsRepository}.
 *
 * @author Rob Winch
 * @since 6.4
 */
class HttpSessionPublicKeyCredentialRequestOptionsRepositoryTests {

	private HttpSessionPublicKeyCredentialRequestOptionsRepository repository = new HttpSessionPublicKeyCredentialRequestOptionsRepository();

	private MockHttpServletRequest request = new MockHttpServletRequest();

	private MockHttpServletResponse response = new MockHttpServletResponse();

	@Test
	void integrationTests() {
		PublicKeyCredentialRequestOptions expected = TestPublicKeyCredentialRequestOptions.create().build();
		this.repository.save(this.request, this.response, expected);
		Object attrValue = this.request.getSession()
			.getAttribute(HttpSessionPublicKeyCredentialRequestOptionsRepository.DEFAULT_ATTR_NAME);
		assertThat(attrValue).isEqualTo(expected);
		PublicKeyCredentialRequestOptions loadOptions = this.repository.load(this.request);
		assertThat(loadOptions).isEqualTo(expected);

		this.repository.save(this.request, this.response, null);

		Object attrValueAfterRemoval = this.request.getSession()
			.getAttribute(HttpSessionPublicKeyCredentialRequestOptionsRepository.DEFAULT_ATTR_NAME);
		assertThat(attrValueAfterRemoval).isNull();
		assertThat(this.request.getSession().getAttributeNames())
			.doesNotHaveToString(HttpSessionPublicKeyCredentialRequestOptionsRepository.DEFAULT_ATTR_NAME);
		PublicKeyCredentialRequestOptions loadOptionsAfterRemoval = this.repository.load(this.request);
		assertThat(loadOptionsAfterRemoval).isNull();
	}

	@Test
	void loadWhenNullSessionThenDoesNotCreate() {
		PublicKeyCredentialRequestOptions options = this.repository.load(this.request);
		assertThat(options).isNull();
		assertThat(this.request.getSession(false)).isNull();
	}

	@Test
	void saveWhenSetAttrThenCustomAttr() {
		PublicKeyCredentialRequestOptions expected = TestPublicKeyCredentialRequestOptions.create().build();
		String customAttr = "custom-attr";
		this.repository.setAttrName(customAttr);
		this.repository.save(this.request, this.response, expected);
		assertThat(this.request.getSession().getAttribute(customAttr)).isEqualTo(expected);
	}

	@Test
	void loadWhenSetAttrThenCustomAttr() {
		PublicKeyCredentialRequestOptions expected = TestPublicKeyCredentialRequestOptions.create().build();
		String customAttr = "custom-attr";
		this.repository.setAttrName(customAttr);
		this.request.getSession().setAttribute(customAttr, expected);
		PublicKeyCredentialRequestOptions actual = this.repository.load(this.request);
		assertThat(actual).isEqualTo(expected);
	}

}
