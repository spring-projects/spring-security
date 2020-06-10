/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.web.header.writers.frameoptions;

import java.util.Collection;

import org.springframework.util.Assert;

/**
 * Implementation which checks the supplied origin against a list of allowed origins.
 *
 * @author Marten Deinum
 * @since 3.2
 * @deprecated ALLOW-FROM is an obsolete directive that no longer works in modern browsers. Instead use
 * Content-Security-Policy with the
 * <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors">frame-ancestors</a>
 * directive.
 */
@Deprecated
public final class WhiteListedAllowFromStrategy extends
		AbstractRequestParameterAllowFromStrategy {

	private final Collection<String> allowed;

	/**
	 * Creates a new instance
	 * @param allowed the origins that are allowed.
	 */
	public WhiteListedAllowFromStrategy(Collection<String> allowed) {
		Assert.notEmpty(allowed, "Allowed origins cannot be empty.");
		this.allowed = allowed;
	}

	@Override
	protected boolean allowed(String allowFromOrigin) {
		return allowed.contains(allowFromOrigin);
	}
}
