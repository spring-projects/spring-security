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

package org.springframework.security.web.access.intercept;

import org.jspecify.annotations.Nullable;

import org.springframework.util.Assert;

/**
 * @author Luke Taylor
 * @since 2.0
 */
public class RequestKey {

	private final String url;

	private final @Nullable String method;

	public RequestKey(String url) {
		this(url, null);
	}

	public RequestKey(String url, @Nullable String method) {
		Assert.notNull(url, "url cannot be null");
		this.url = url;
		this.method = method;
	}

	String getUrl() {
		return this.url;
	}

	@Nullable String getMethod() {
		return this.method;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof RequestKey key)) {
			return false;
		}
		if (!this.url.equals(key.url)) {
			return false;
		}
		if (this.method == null) {
			return key.method == null;
		}
		return this.method.equals(key.method);
	}

	@Override
	public int hashCode() {
		int result = this.url.hashCode();
		result = 31 * result + ((this.method != null) ? this.method.hashCode() : 0);
		return result;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder(this.url.length() + 7);
		sb.append("[");
		if (this.method != null) {
			sb.append(this.method).append(",");
		}
		sb.append(this.url);
		sb.append("]");
		return sb.toString();
	}

}
