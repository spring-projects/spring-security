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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * @author Rob Winch
 */
public class HttpSessionCsrfTokenRepositoryTests {

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	private CsrfToken token;

	private HttpSessionCsrfTokenRepository repo;

	@BeforeEach
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
		String loadedToken = (String) this.request.getSession().getAttribute(attrName);
		assertThat(loadedToken).isEqualTo(tokenToSave.getToken());
	}

	@Test
	public void saveTokenCustomSessionAttribute() {
		CsrfToken tokenToSave = new DefaultCsrfToken("123", "abc", "def");
		String sessionAttributeName = "custom";
		this.repo.setSessionAttributeName(sessionAttributeName);
		this.repo.saveToken(tokenToSave, this.request, this.response);
		String loadedToken = (String) this.request.getSession().getAttribute(sessionAttributeName);
		assertThat(loadedToken).isEqualTo(tokenToSave.getToken());
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

	@Test
	public void withXorRandomSecretEnabledWhenSecureRandomIsNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> HttpSessionCsrfTokenRepository.withXorRandomSecretEnabled(null))
				.withMessage("secureRandom cannot be null");
	}

	@Test
	public void withXorRandomSecretEnabledWhenUsedThenReturnsUniqueTokens() {
		HttpSessionCsrfTokenRepository repo = HttpSessionCsrfTokenRepository.withXorRandomSecretEnabled();

		CsrfToken csrfToken = repo.generateToken(this.request);
		String token1 = csrfToken.getToken();
		String token2 = csrfToken.getToken();
		assertThat(token1).isNotEqualTo(token2);
		assertThat(csrfToken.matches(token1)).isTrue();
		assertThat(csrfToken.matches(token2)).isTrue();
	}

	@Test
	public void generateTokenWhenSetXorRandomSecretEnabledTrueThenReturnsUniqueTokens() {
		this.repo.setXorRandomSecretEnabled(true);

		CsrfToken csrfToken = this.repo.generateToken(this.request);
		String token1 = csrfToken.getToken();
		String token2 = csrfToken.getToken();
		assertThat(token1).isNotEqualTo(token2);
		assertThat(csrfToken.matches(token1)).isTrue();
		assertThat(csrfToken.matches(token2)).isTrue();
	}

	@Test
	public void generateTokenWhenSetXorRandomSecretEnabledFalseThenReturnsNonUniqueTokens() {
		this.repo.setXorRandomSecretEnabled(false);

		CsrfToken csrfToken = this.repo.generateToken(this.request);
		String token1 = csrfToken.getToken();
		String token2 = csrfToken.getToken();
		assertThat(token1).isEqualTo(token2);
		assertThat(csrfToken.matches(token1)).isTrue();
		assertThat(csrfToken.matches(token2)).isTrue();
	}

	@Test
	public void loadTokenWhenSetXorRandomSecretEnabledTrueThenReturnsUniqueTokens() {
		this.repo.saveToken(new DefaultCsrfToken("123", "abc", "def"), this.request, this.response);
		this.repo.setXorRandomSecretEnabled(true);

		CsrfToken csrfToken = this.repo.loadToken(this.request);
		String token1 = csrfToken.getToken();
		String token2 = csrfToken.getToken();
		assertThat(token1).isNotEqualTo(token2);
		assertThat(csrfToken.matches(token1)).isTrue();
		assertThat(csrfToken.matches(token2)).isTrue();
	}

	@Test
	public void saveTokenWhenSetXorRandomSecretEnabledTrueThenRawTokenIsSaved() {
		this.repo.setXorRandomSecretEnabled(true);

		CsrfToken csrfToken = this.repo.generateToken(this.request);
		this.repo.saveToken(csrfToken, this.request, this.response);

		String sessionAttributeName = this.request.getSession().getAttributeNames().nextElement();
		String tokenValue = (String) this.request.getSession().getAttribute(sessionAttributeName);
		assertThat(tokenValue).isEqualTo(((DefaultCsrfToken) csrfToken).getRawToken());
	}

	@Test
	public void matchesWhenSetXorRandomSecretEnabledTrueAndTokensNotEqualThenFalse() {
		this.repo.setXorRandomSecretEnabled(true);

		CsrfToken csrfToken1 = this.repo.generateToken(this.request);
		CsrfToken csrfToken2 = this.repo.generateToken(this.request);
		assertThat(csrfToken1.matches(csrfToken2.getToken())).isFalse();
	}

}
