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

import java.util.function.Supplier;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.util.Assert;

/**
 * An implementation of the {@link CsrfTokenRequestHandler} and
 * {@link CsrfTokenRequestResolver} interfaces that is capable of making the
 * {@link CsrfToken} available as a request attribute and resolving the token value as
 * either a header or parameter value of the request.
 *
 * @author Steve Riesenberg
 * @since 5.8
 */
public class CsrfTokenRequestProcessor implements CsrfTokenRequestHandler, CsrfTokenRequestResolver {

	private String csrfRequestAttributeName;

	private CsrfTokenRepository tokenRepository = new HttpSessionCsrfTokenRepository();

	/**
	 * Sets the {@link CsrfTokenRepository} to use.
	 * @param tokenRepository the {@link CsrfTokenRepository} to use. Default
	 * {@link HttpSessionCsrfTokenRepository}
	 */
	public void setTokenRepository(CsrfTokenRepository tokenRepository) {
		Assert.notNull(tokenRepository, "tokenRepository cannot be null");
		this.tokenRepository = tokenRepository;
	}

	/**
	 * The {@link CsrfToken} is available as a request attribute named
	 * {@code CsrfToken.class.getName()}. By default, an additional request attribute that
	 * is the same as {@link CsrfToken#getParameterName()} is set. This attribute allows
	 * overriding the additional attribute.
	 * @param csrfRequestAttributeName the name of an additional request attribute with
	 * the value of the CsrfToken. Default is {@link CsrfToken#getParameterName()}
	 */
	public final void setCsrfRequestAttributeName(String csrfRequestAttributeName) {
		this.csrfRequestAttributeName = csrfRequestAttributeName;
	}

	@Override
	public DeferredCsrfToken handle(HttpServletRequest request, HttpServletResponse response) {
		Assert.notNull(request, "request cannot be null");
		Assert.notNull(response, "response cannot be null");

		request.setAttribute(HttpServletResponse.class.getName(), response);
		DeferredCsrfToken deferredCsrfToken = new RepositoryDeferredCsrfToken(request, response);
		CsrfToken csrfToken = new SupplierCsrfToken(deferredCsrfToken::get);
		request.setAttribute(CsrfToken.class.getName(), csrfToken);
		String csrfAttrName = (this.csrfRequestAttributeName != null) ? this.csrfRequestAttributeName
				: csrfToken.getParameterName();
		request.setAttribute(csrfAttrName, csrfToken);
		return deferredCsrfToken;
	}

	@Override
	public String resolveCsrfTokenValue(HttpServletRequest request, CsrfToken csrfToken) {
		Assert.notNull(request, "request cannot be null");
		Assert.notNull(csrfToken, "csrfToken cannot be null");
		String actualToken = request.getHeader(csrfToken.getHeaderName());
		if (actualToken == null) {
			actualToken = request.getParameter(csrfToken.getParameterName());
		}
		return actualToken;
	}

	private static final class SupplierCsrfToken implements CsrfToken {

		private final Supplier<CsrfToken> csrfTokenSupplier;

		private SupplierCsrfToken(Supplier<CsrfToken> csrfTokenSupplier) {
			this.csrfTokenSupplier = csrfTokenSupplier;
		}

		@Override
		public String getHeaderName() {
			return getDelegate().getHeaderName();
		}

		@Override
		public String getParameterName() {
			return getDelegate().getParameterName();
		}

		@Override
		public String getToken() {
			return getDelegate().getToken();
		}

		private CsrfToken getDelegate() {
			CsrfToken delegate = this.csrfTokenSupplier.get();
			if (delegate == null) {
				throw new IllegalStateException("csrfTokenSupplier returned null delegate");
			}
			return delegate;
		}

	}

	private final class RepositoryDeferredCsrfToken implements DeferredCsrfToken {

		private final HttpServletRequest request;

		private final HttpServletResponse response;

		private CsrfToken csrfToken;

		private Boolean missingToken;

		RepositoryDeferredCsrfToken(HttpServletRequest request, HttpServletResponse response) {
			this.request = request;
			this.response = response;
		}

		@Override
		public CsrfToken get() {
			init();
			return this.csrfToken;
		}

		@Override
		public boolean isGenerated() {
			init();
			return this.missingToken;
		}

		private void init() {
			if (this.csrfToken != null) {
				return;
			}
			this.csrfToken = CsrfTokenRequestProcessor.this.tokenRepository.loadToken(this.request);
			this.missingToken = (this.csrfToken == null);
			if (this.missingToken) {
				this.csrfToken = CsrfTokenRequestProcessor.this.tokenRepository.generateToken(this.request);
				CsrfTokenRequestProcessor.this.tokenRepository.saveToken(this.csrfToken, this.request, this.response);
			}
		}

	}

}
