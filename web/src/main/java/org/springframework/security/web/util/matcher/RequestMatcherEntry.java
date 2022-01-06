/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.web.util.matcher;

/**
 * A rich object for associating a {@link RequestMatcher} to another object.
 *
 * @author Marcus Da Coregio
 * @since 5.5.5
 */
public class RequestMatcherEntry<T> {

	private final RequestMatcher requestMatcher;

	private final T entry;

	public RequestMatcherEntry(RequestMatcher requestMatcher, T entry) {
		this.requestMatcher = requestMatcher;
		this.entry = entry;
	}

	public RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}

	public T getEntry() {
		return this.entry;
	}

}
