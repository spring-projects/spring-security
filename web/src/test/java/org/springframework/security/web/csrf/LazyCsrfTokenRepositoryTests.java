/*
 * Copyright 2012-2016 the original author or authors.
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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * @author Rob Winch
 */
@ExtendWith(MockitoExtension.class)
public class LazyCsrfTokenRepositoryTests {

	@Mock
	CsrfTokenRepository delegate;

	@Mock
	HttpServletRequest request;

	@Mock
	HttpServletResponse response;

	@InjectMocks
	LazyCsrfTokenRepository repository;

	DefaultCsrfToken token;

	@BeforeEach
	public void setup() {
		this.token = new DefaultCsrfToken("header", "param", "token");
	}

	@Test
	public void constructNullDelegateThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new LazyCsrfTokenRepository(null));
	}

	@Test
	public void generateTokenNullResponseAttribute() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.repository.generateToken(mock(HttpServletRequest.class)));
	}

	@Test
	public void generateTokenGetTokenSavesToken() {
		given(this.delegate.generateToken(this.request)).willReturn(this.token);
		given(this.request.getAttribute(HttpServletResponse.class.getName())).willReturn(this.response);
		CsrfToken newToken = this.repository.generateToken(this.request);
		newToken.getToken();
		verify(this.delegate).saveToken(this.token, this.request, this.response);
	}

	@Test
	public void saveNonNullDoesNothing() {
		this.repository.saveToken(this.token, this.request, this.response);
		verifyNoMoreInteractions(this.delegate);
	}

	@Test
	public void saveNullDelegates() {
		this.repository.saveToken(null, this.request, this.response);
		verify(this.delegate).saveToken(null, this.request, this.response);
	}

	@Test
	public void loadTokenDelegates() {
		given(this.delegate.loadToken(this.request)).willReturn(this.token);
		CsrfToken loadToken = this.repository.loadToken(this.request);
		assertThat(loadToken).isSameAs(this.token);
		verify(this.delegate).loadToken(this.request);
	}

	@Test
	public void loadTokenWhenDeferLoadToken() {
		given(this.delegate.loadToken(this.request)).willReturn(this.token);
		this.repository.setDeferLoadToken(true);
		CsrfToken loadToken = this.repository.loadToken(this.request);
		verifyNoInteractions(this.delegate);
		assertThat(loadToken.getToken()).isEqualTo(this.token.getToken());
		assertThat(loadToken.getHeaderName()).isEqualTo(this.token.getHeaderName());
		assertThat(loadToken.getParameterName()).isEqualTo(this.token.getParameterName());
	}

}
