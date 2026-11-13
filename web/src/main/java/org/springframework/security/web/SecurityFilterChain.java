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

package org.springframework.security.web;

import java.util.List;

import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;

/**
 * Defines a filter chain which is capable of being matched against an
 * {@code HttpServletRequest}. in order to decide whether it applies to that request.
 * <p>
 * Used to configure a {@code FilterChainProxy}.
 *
 * @author Luke Taylor
 * @since 3.1
 */
public interface SecurityFilterChain {

	boolean matches(HttpServletRequest request);

	List<Filter> getFilters();

	/**
	 * Returns a human-readable name identifying this chain, intended for
	 * diagnostics such as log messages. May be {@code null} when no
	 * meaningful name is available.
	 * <p>
	 * The returned value is intended for diagnostics only; it is not
	 * stable across implementations and MUST NOT be used as a key for
	 * authorization, routing, or any other functional decision.
	 * <p>
	 * Implementations should return quickly and should not throw exceptions.
	 * Implementations that wrap or delegate to another {@code SecurityFilterChain}
	 * are responsible for forwarding {@code getName()} appropriately when chain
	 * identity matters to consumers.
	 *
	 * @return the chain name, or {@code null} if unavailable
	 * @since 7.1
	 */
	default @Nullable String getName() {
		return null;
	}

}
