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

import org.springframework.util.Assert;

/**
 * A {@link CsrfTokenRepository} that delays saving new {@link CsrfToken} until the
 * attributes of the {@link CsrfToken} that were generated are accessed.
 *
 * @author Rob Winch
 * @since 4.1
 * @deprecated Use
 * {@link CsrfTokenRepository#loadDeferredToken(HttpServletRequest, HttpServletResponse)}
 * which returns a {@link DeferredCsrfToken}
 */
@Deprecated
public final class LazyCsrfTokenRepository implements CsrfTokenRepository {

	/**
	 * The {@link HttpServletRequest} attribute name that the {@link HttpServletResponse}
	 * must be on.
	 */
	private static final String HTTP_RESPONSE_ATTR = HttpServletResponse.class.getName();

	private final CsrfTokenRepository delegate;

	private boolean deferLoadToken;

	/**
	 * Creates a new instance
	 * @param delegate the {@link CsrfTokenRepository} to use. Cannot be null
	 * @throws IllegalArgumentException if delegate is null.
	 */
	public LazyCsrfTokenRepository(CsrfTokenRepository delegate) {
		Assert.notNull(delegate, "delegate cannot be null");
		this.delegate = delegate;
	}

	/**
	 * Determines if {@link #loadToken(HttpServletRequest)} should be lazily loaded.
	 * @param deferLoadToken true if should lazily load
	 * {@link #loadToken(HttpServletRequest)}. Default false.
	 */
	public void setDeferLoadToken(boolean deferLoadToken) {
		this.deferLoadToken = deferLoadToken;
	}

	/**
	 * Generates a new token
	 * @param request the {@link HttpServletRequest} to use. The
	 * {@link HttpServletRequest} must have the {@link HttpServletResponse} as an
	 * attribute with the name of <code>HttpServletResponse.class.getName()</code>
	 */
	@Override
	public CsrfToken generateToken(HttpServletRequest request) {
		return wrap(request, this.delegate.generateToken(request));
	}

	/**
	 * Does nothing if the {@link CsrfToken} is not null. Saving is done only when the
	 * {@link CsrfToken#getToken()} is accessed from
	 * {@link #generateToken(HttpServletRequest)}. If it is null, then the save is
	 * performed immediately.
	 */
	@Override
	public void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response) {
		if (token == null) {
			this.delegate.saveToken(token, request, response);
		}
	}

	/**
	 * Delegates to the injected {@link CsrfTokenRepository}
	 */
	@Override
	public CsrfToken loadToken(HttpServletRequest request) {
		if (this.deferLoadToken) {
			return new LazyLoadCsrfToken(request, this.delegate);
		}
		return this.delegate.loadToken(request);
	}

	private CsrfToken wrap(HttpServletRequest request, CsrfToken token) {
		HttpServletResponse response = getResponse(request);
		return new SaveOnAccessCsrfToken(this.delegate, request, response, token);
	}

	private HttpServletResponse getResponse(HttpServletRequest request) {
		HttpServletResponse response = (HttpServletResponse) request.getAttribute(HTTP_RESPONSE_ATTR);
		Assert.notNull(response, () -> "The HttpServletRequest attribute must contain an HttpServletResponse "
				+ "for the attribute " + HTTP_RESPONSE_ATTR);
		return response;
	}

	private final class LazyLoadCsrfToken implements CsrfToken {

		private final HttpServletRequest request;

		private final CsrfTokenRepository tokenRepository;

		private CsrfToken token;

		private LazyLoadCsrfToken(HttpServletRequest request, CsrfTokenRepository tokenRepository) {
			this.request = request;
			this.tokenRepository = tokenRepository;
		}

		private CsrfToken getDelegate() {
			if (this.token != null) {
				return this.token;
			}
			// load from the delegate repository
			this.token = LazyCsrfTokenRepository.this.delegate.loadToken(this.request);
			if (this.token == null) {
				// return a generated token that is lazily saved since
				// LazyCsrfTokenRepository#loadToken always returns a value
				this.token = generateToken(this.request);
			}
			return this.token;
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

		@Override
		public String toString() {
			return "LazyLoadCsrfToken{" + "token=" + this.token + '}';
		}

	}

	private static final class SaveOnAccessCsrfToken implements CsrfToken {

		private transient CsrfTokenRepository tokenRepository;

		private transient HttpServletRequest request;

		private transient HttpServletResponse response;

		private final CsrfToken delegate;

		SaveOnAccessCsrfToken(CsrfTokenRepository tokenRepository, HttpServletRequest request,
				HttpServletResponse response, CsrfToken delegate) {
			this.tokenRepository = tokenRepository;
			this.request = request;
			this.response = response;
			this.delegate = delegate;
		}

		@Override
		public String getHeaderName() {
			return this.delegate.getHeaderName();
		}

		@Override
		public String getParameterName() {
			return this.delegate.getParameterName();
		}

		@Override
		public String getToken() {
			saveTokenIfNecessary();
			return this.delegate.getToken();
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null || getClass() != obj.getClass()) {
				return false;
			}
			SaveOnAccessCsrfToken other = (SaveOnAccessCsrfToken) obj;
			if (this.delegate == null) {
				if (other.delegate != null) {
					return false;
				}
			}
			else if (!this.delegate.equals(other.delegate)) {
				return false;
			}
			return true;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + ((this.delegate == null) ? 0 : this.delegate.hashCode());
			return result;
		}

		@Override
		public String toString() {
			return "SaveOnAccessCsrfToken [delegate=" + this.delegate + "]";
		}

		private void saveTokenIfNecessary() {
			if (this.tokenRepository == null) {
				return;
			}
			synchronized (this) {
				if (this.tokenRepository != null) {
					this.tokenRepository.saveToken(this.delegate, this.request, this.response);
					this.tokenRepository = null;
					this.request = null;
					this.response = null;
				}
			}
		}

	}

}
