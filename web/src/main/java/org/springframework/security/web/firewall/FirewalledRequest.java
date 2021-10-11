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

package org.springframework.security.web.firewall;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

/**
 * Request wrapper which is returned by the {@code HttpFirewall} interface.
 * <p>
 * The only difference is the {@code reset} method which allows some or all of the state
 * to be reset by the {@code FilterChainProxy} when the request leaves the security filter
 * chain.
 *
 * @author Luke Taylor
 */
public abstract class FirewalledRequest extends HttpServletRequestWrapper {

	/**
	 * Constructs a request object wrapping the given request.
	 * @throws IllegalArgumentException if the request is null
	 */
	public FirewalledRequest(HttpServletRequest request) {
		super(request);
	}

	/**
	 * This method will be called once the request has passed through the security filter
	 * chain, when it is about to proceed to the application proper.
	 * <p>
	 * An implementation can thus choose to modify the state of the request for the
	 * security infrastructure, while still maintaining the original
	 * {@link HttpServletRequest}.
	 */
	public abstract void reset();

	@Override
	public String toString() {
		return "FirewalledRequest[ " + getRequest() + "]";
	}

}
