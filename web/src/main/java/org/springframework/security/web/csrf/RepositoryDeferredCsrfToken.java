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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * @author Rob Winch
 * @author Steve Riesenberg
 * @since 5.8
 */
final class RepositoryDeferredCsrfToken implements DeferredCsrfToken {

	private final CsrfTokenRepository csrfTokenRepository;

	private final HttpServletRequest request;

	private final HttpServletResponse response;

	private CsrfToken csrfToken;

	private boolean missingToken;

	RepositoryDeferredCsrfToken(CsrfTokenRepository csrfTokenRepository, HttpServletRequest request,
			HttpServletResponse response) {
		this.csrfTokenRepository = csrfTokenRepository;
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

		this.csrfToken = this.csrfTokenRepository.loadToken(this.request);
		this.missingToken = (this.csrfToken == null);
		if (this.missingToken) {
			this.csrfToken = this.csrfTokenRepository.generateToken(this.request);
			this.csrfTokenRepository.saveToken(this.csrfToken, this.request, this.response);
		}
	}

}
