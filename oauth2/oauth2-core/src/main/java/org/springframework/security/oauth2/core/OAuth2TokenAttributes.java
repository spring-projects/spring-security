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

package org.springframework.security.oauth2.core;

import java.util.Collections;
import java.util.Map;

/**
 * A domain object that wraps the attributes of an OAuth 2.0 token.
 *
 * @author Clement Ng
 * @since 5.2
 */
public final class OAuth2TokenAttributes {
	private final Map<String, Object> attributes;

	/**
	 * Constructs an {@code OAuth2TokenAttributes} using the provided parameters.
	 *
	 * @param attributes the attributes of the OAuth 2.0 token
	 */
	public OAuth2TokenAttributes(Map<String, Object> attributes) {
		this.attributes = Collections.unmodifiableMap(attributes);
	}

	/**
	 * Gets the attributes of the OAuth 2.0 token in map form.
	 *
	 * @return a {@link Map} of the attribute's objects keyed by the attribute's names
	 */
	public Map<String, Object> getAttributes() {
		return attributes;
	}

	/**
	 * Gets the attribute of the OAuth 2.0 token corresponding to the name.
	 *
	 * @param name the name to lookup in the attributes
	 * @return the object corresponding to the name in the attributes
	 */
	public <A> A getAttribute(String name) {
		return (A) this.attributes.get(name);
	}
}
