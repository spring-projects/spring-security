/*
 * Copyright 2004-present the original author or authors.
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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jspecify.annotations.Nullable;
import org.springframework.util.Assert;

import java.security.SecureRandom;
import java.util.function.Supplier;

/**
 * An implementation of the {@link CsrfTokenRequestHandler} interface that is capable of
 * masking the value of the {@link CsrfToken} on each request and resolving the raw token
 * value from the masked value as either a header or parameter value of the request.
 *
 * @author Steve Riesenberg
 * @author Yoobin Yoon
 * @author Cheol Jeon
 * @since 5.8
 */
public final class XorCsrfTokenRequestAttributeHandler extends CsrfTokenRequestAttributeHandler {

	private static final Log logger = LogFactory.getLog(XorCsrfTokenRequestAttributeHandler.class);

	private CsrfTokenEncoder csrfTokenEncoder = new XorCsrfTokenEncoder();

	/**
	 * Specifies the {@code SecureRandom} used to generate random bytes that are used to
	 * mask the value of the {@link CsrfToken} on each request.
	 * @param secureRandom the {@code SecureRandom} to use to generate random bytes
	 */
	public void setSecureRandom(SecureRandom secureRandom) {
		Assert.notNull(secureRandom, "secureRandom cannot be null");
		this.csrfTokenEncoder = new XorCsrfTokenEncoder(secureRandom);
	}

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
			Supplier<CsrfToken> deferredCsrfToken) {
		Assert.notNull(request, "request cannot be null");
		Assert.notNull(response, "response cannot be null");
		Assert.notNull(deferredCsrfToken, "deferredCsrfToken cannot be null");
		Supplier<CsrfToken> updatedCsrfToken = deferCsrfTokenUpdate(deferredCsrfToken);
		super.handle(request, response, updatedCsrfToken);
	}

	private Supplier<CsrfToken> deferCsrfTokenUpdate(Supplier<CsrfToken> csrfTokenSupplier) {
		return new CachedCsrfTokenSupplier(() -> {
			CsrfToken csrfToken = csrfTokenSupplier.get();
			Assert.state(csrfToken != null, "csrfToken supplier returned null");
			String updatedToken = csrfTokenEncoder.encode(csrfToken.getToken());
			return new DefaultCsrfToken(csrfToken.getHeaderName(), csrfToken.getParameterName(), updatedToken);
		});
	}

	@Override
	public @Nullable String resolveCsrfTokenValue(HttpServletRequest request, CsrfToken csrfToken) {
		String actualToken = super.resolveCsrfTokenValue(request, csrfToken);
		if (actualToken == null) {
			return null;
		}
		return csrfTokenEncoder.decode(actualToken, csrfToken.getToken());
	}

	private static final class CachedCsrfTokenSupplier implements Supplier<CsrfToken> {

		private final Supplier<CsrfToken> delegate;

		private @Nullable CsrfToken csrfToken;

		private CachedCsrfTokenSupplier(Supplier<CsrfToken> delegate) {
			this.delegate = delegate;
		}

		@Override
		public CsrfToken get() {
			if (this.csrfToken == null) {
				this.csrfToken = this.delegate.get();
			}
			return this.csrfToken;
		}

	}

}
