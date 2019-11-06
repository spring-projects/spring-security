/*
 * Copyright 2002-2017 the original author or authors.
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

package org.springframework.security.web.server.util.matcher;

/**
 * A rich object for associating a {@link ServerWebExchangeMatcher} to another object.
 * @author Rob Winch
 * @since 5.0
 */
public class ServerWebExchangeMatcherEntry<T> {
	private final ServerWebExchangeMatcher matcher;
	private final T entry;

	public ServerWebExchangeMatcherEntry(ServerWebExchangeMatcher matcher, T entry) {
		this.matcher = matcher;
		this.entry = entry;
	}

	public ServerWebExchangeMatcher getMatcher() {
		return matcher;
	}

	public T getEntry() {
		return entry;
	}
}
