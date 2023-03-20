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

package org.springframework.security.web.context;

import java.util.Arrays;
import java.util.List;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.core.context.DeferredSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.util.Assert;

/**
 * @author Steve Riesenberg
 * @author Josh Cummings
 * @since 5.8
 */
public final class DelegatingSecurityContextRepository implements SecurityContextRepository {

	private final List<SecurityContextRepository> delegates;

	public DelegatingSecurityContextRepository(SecurityContextRepository... delegates) {
		this(Arrays.asList(delegates));
	}

	public DelegatingSecurityContextRepository(List<SecurityContextRepository> delegates) {
		Assert.notEmpty(delegates, "delegates cannot be empty");
		this.delegates = delegates;
	}

	@Override
	public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
		return loadDeferredContext(requestResponseHolder.getRequest()).get();
	}

	@Override
	public DeferredSecurityContext loadDeferredContext(HttpServletRequest request) {
		DeferredSecurityContext deferredSecurityContext = null;
		for (SecurityContextRepository delegate : this.delegates) {
			if (deferredSecurityContext == null) {
				deferredSecurityContext = delegate.loadDeferredContext(request);
			}
			else {
				DeferredSecurityContext next = delegate.loadDeferredContext(request);
				deferredSecurityContext = new DelegatingDeferredSecurityContext(deferredSecurityContext, next);
			}
		}
		return deferredSecurityContext;
	}

	@Override
	public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
		for (SecurityContextRepository delegate : this.delegates) {
			delegate.saveContext(context, request, response);
		}
	}

	@Override
	public boolean containsContext(HttpServletRequest request) {
		for (SecurityContextRepository delegate : this.delegates) {
			if (delegate.containsContext(request)) {
				return true;
			}
		}
		return false;
	}

	static final class DelegatingDeferredSecurityContext implements DeferredSecurityContext {

		private final DeferredSecurityContext previous;

		private final DeferredSecurityContext next;

		DelegatingDeferredSecurityContext(DeferredSecurityContext previous, DeferredSecurityContext next) {
			this.previous = previous;
			this.next = next;
		}

		@Override
		public SecurityContext get() {
			SecurityContext securityContext = this.previous.get();
			if (!this.previous.isGenerated()) {
				return securityContext;
			}
			return this.next.get();
		}

		@Override
		public boolean isGenerated() {
			return this.previous.isGenerated() && this.next.isGenerated();
		}

	}

}
