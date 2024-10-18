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

package org.springframework.security.web.webauthn.registration;

import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.TestPublicKeyCredentialCreationOptions;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for
 * {@link org.springframework.security.web.webauthn.authentication.HttpSessionPublicKeyCredentialRequestOptionsRepository}.
 *
 * @author Rob Winch
 * @since 6.4
 */
class HttpSessionPublicKeyCredentialCreationOptionsRepositoryTests {

	private HttpSessionPublicKeyCredentialCreationOptionsRepository repository = new HttpSessionPublicKeyCredentialCreationOptionsRepository();

	private MockHttpServletRequest request = new MockHttpServletRequest();

	private MockHttpServletResponse response = new MockHttpServletResponse();

	@Test
	void integrationTests() {
		PublicKeyCredentialCreationOptions expected = TestPublicKeyCredentialCreationOptions
			.createPublicKeyCredentialCreationOptions()
			.build();
		this.repository.save(this.request, this.response, expected);
		Object attrValue = this.request.getSession()
			.getAttribute(HttpSessionPublicKeyCredentialCreationOptionsRepository.DEFAULT_ATTR_NAME);
		assertThat(attrValue).isEqualTo(expected);
		PublicKeyCredentialCreationOptions loadOptions = this.repository.load(this.request);
		assertThat(loadOptions).isEqualTo(expected);

		this.repository.save(this.request, this.response, null);

		Object attrValueAfterRemoval = this.request.getSession()
			.getAttribute(HttpSessionPublicKeyCredentialCreationOptionsRepository.DEFAULT_ATTR_NAME);
		assertThat(attrValueAfterRemoval).isNull();
		assertThat(this.request.getSession().getAttributeNames())
			.doesNotHaveToString(HttpSessionPublicKeyCredentialCreationOptionsRepository.DEFAULT_ATTR_NAME);
		PublicKeyCredentialCreationOptions loadOptionsAfterRemoval = this.repository.load(this.request);
		assertThat(loadOptionsAfterRemoval).isNull();
	}

	@Test
	void loadWhenNullSessionThenDoesNotCreate() {
		PublicKeyCredentialCreationOptions options = this.repository.load(this.request);
		assertThat(options).isNull();
		assertThat(this.request.getSession(false)).isNull();
	}

	@Test
	void saveWhenSetAttrThenCustomAttr() {
		PublicKeyCredentialCreationOptions expected = TestPublicKeyCredentialCreationOptions
			.createPublicKeyCredentialCreationOptions()
			.build();
		String customAttr = "custom-attr";
		this.repository.setAttrName(customAttr);
		this.repository.save(this.request, this.response, expected);
		assertThat(this.request.getSession().getAttribute(customAttr)).isEqualTo(expected);
	}

	@Test
	void loadWhenSetAttrThenCustomAttr() {
		PublicKeyCredentialCreationOptions expected = TestPublicKeyCredentialCreationOptions
			.createPublicKeyCredentialCreationOptions()
			.build();
		String customAttr = "custom-attr";
		this.repository.setAttrName(customAttr);
		this.request.getSession().setAttribute(customAttr, expected);
		PublicKeyCredentialCreationOptions actual = this.repository.load(this.request);
		assertThat(actual).isEqualTo(expected);
	}

}
