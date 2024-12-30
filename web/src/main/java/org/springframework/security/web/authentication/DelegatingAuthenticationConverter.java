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

package org.springframework.security.web.authentication;

import java.util.List;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * A {@link AuthenticationConverter}, that iterates over multiple
 * {@link AuthenticationConverter}. The first non-null {@link Authentication} will be used
 * as a result.
 *
 * @author Max Batischev
 * @since 6.3
 */
public final class DelegatingAuthenticationConverter implements AuthenticationConverter {

	private final List<AuthenticationConverter> delegates;

	public DelegatingAuthenticationConverter(List<AuthenticationConverter> delegates) {
		Assert.notEmpty(delegates, "delegates cannot be null");
		this.delegates = List.copyOf(delegates);
	}

	public DelegatingAuthenticationConverter(AuthenticationConverter... delegates) {
		Assert.notEmpty(delegates, "delegates cannot be null");
		this.delegates = List.of(delegates);
	}

	@Override
	public Authentication convert(HttpServletRequest request) {
		for (AuthenticationConverter delegate : this.delegates) {
			Authentication authentication = delegate.convert(request);
			if (authentication != null) {
				return authentication;
			}
		}
		return null;
	}

}
