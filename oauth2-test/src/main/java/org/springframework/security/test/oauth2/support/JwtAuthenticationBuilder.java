/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.test.oauth2.support;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 */
public class JwtAuthenticationBuilder<T extends DefaultOAuth2AuthenticationBuilder<T>>
		extends
		DefaultOAuth2AuthenticationBuilder<T> {

	protected Map<String, Object> headers = JwtSupport.DEFAULT_HEADERS;

	private boolean isHeadersSet = false;

	public T claims(final Map<String, Object> claims) {
		return attributes(claims);
	}

	public T claim(final String name, final Object value) {
		return attribute(name, value);
	}

	public T headers(final Map<String, Object> headers) {
		headers.entrySet().stream().forEach(e -> this.header(e.getKey(), e.getValue()));
		return downCast();
	}

	public T header(final String name, final Object value) {
		assert (name != null);
		if (this.isHeadersSet == false) {
			this.headers = new HashMap<>();
			this.isHeadersSet = true;
		}
		this.headers.put(name, value);
		return downCast();
	}

}
