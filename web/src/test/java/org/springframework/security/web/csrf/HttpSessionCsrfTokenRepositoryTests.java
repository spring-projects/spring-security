/*
 * Copyright 2002-2013 the original author or authors.
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

import org.junit.Before;
import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * @author Rob Winch
 *
 */
public class HttpSessionCsrfTokenRepositoryTests {

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	private CsrfToken token;

	private HttpSessionCsrfTokenRepository repo;

	@Before
	public void setup() {
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
		this.repo = new HttpSessionCsrfTokenRepository();
	}

	@Test
	public void generateToken() {
		this.token = this.repo.generateToken(this.request);
		assertThat(this.token.getParameterName()).isEqualTo("_csrf");
		assertThat(this.token.getToken()).isNotEmpty();
		CsrfToken loadedToken = this.repo.loadToken(this.request);
		assertThat(loadedToken).isNull();
	}

	@Test
	public void generateCustomParameter() {
		String paramName = "_csrf";
		this.repo.setParameterName(paramName);
		this.token = this.repo.generateToken(this.request);
		assertThat(this.token.getParameterName()).isEqualTo(paramName);
		assertThat(this.token.getToken()).isNotEmpty();
	}

	@Test
	public void generateCustomHeader() {
		String headerName = "CSRF";
		this.repo.setHeaderName(headerName);
		this.token = this.repo.generateToken(this.request);
		assertThat(this.token.getHeaderName()).isEqualTo(headerName);
		assertThat(this.token.getToken()).isNotEmpty();
	}

	@Test
	public void loadTokenNull() {
		assertThat(this.repo.loadToken(this.request)).isNull();
		assertThat(this.request.getSession(false)).isNull();
	}

	@Test
	public void loadTokenNullWhenSessionExists() {
		this.request.getSession();
		assertThat(this.repo.loadToken(this.request)).isNull();
	}

	@Test
	public void saveToken() {
		CsrfToken tokenToSave = new DefaultCsrfToken("123", "abc", "def");
		this.repo.saveToken(tokenToSave, this.request, this.response);
		String attrName = this.request.getSession().getAttributeNames().nextElement();
		CsrfToken loadedToken = (CsrfToken) this.request.getSession().getAttribute(attrName);
		assertThat(loadedToken).isEqualTo(tokenToSave);
	}

	@Test
	public void saveTokenCustomSessionAttribute() {
		CsrfToken tokenToSave = new DefaultCsrfToken("123", "abc", "def");
		String sessionAttributeName = "custom";
		this.repo.setSessionAttributeName(sessionAttributeName);
		this.repo.saveToken(tokenToSave, this.request, this.response);
		CsrfToken loadedToken = (CsrfToken) this.request.getSession().getAttribute(sessionAttributeName);
		assertThat(loadedToken).isEqualTo(tokenToSave);
	}

	@Test
	public void saveTokenNullToken() {
		saveToken();
		this.repo.saveToken(null, this.request, this.response);
		assertThat(this.request.getSession().getAttributeNames().hasMoreElements()).isFalse();
	}

	@Test
	public void saveTokenNullTokenWhenSessionNotExists() {
		this.repo.saveToken(null, this.request, this.response);
		assertThat(this.request.getSession(false)).isNull();
	}

	@Test
	public void setSessionAttributeNameEmpty() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.repo.setSessionAttributeName(""));
	}

	@Test
	public void setSessionAttributeNameNull() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.repo.setSessionAttributeName(null));
	}

	@Test
	public void setParameterNameEmpty() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.repo.setParameterName(""));
	}

	@Test
	public void setParameterNameNull() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.repo.setParameterName(null));
	}

}
