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

package org.springframework.security.oauth2.server.authorization.token;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

/**
 * Default implementation of {@link OAuth2TokenContext}.
 *
 * @author Joe Grandja
 * @since 7.0
 * @see OAuth2TokenContext
 */
public final class DefaultOAuth2TokenContext implements OAuth2TokenContext {

	private final Map<Object, Object> context;

	private DefaultOAuth2TokenContext(Map<Object, Object> context) {
		this.context = Collections.unmodifiableMap(new HashMap<>(context));
	}

	@SuppressWarnings("unchecked")
	@Nullable
	@Override
	public <V> V get(Object key) {
		return hasKey(key) ? (V) this.context.get(key) : null;
	}

	@Override
	public boolean hasKey(Object key) {
		Assert.notNull(key, "key cannot be null");
		return this.context.containsKey(key);
	}

	/**
	 * Returns a new {@link Builder}.
	 * @return the {@link Builder}
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * A builder for {@link DefaultOAuth2TokenContext}.
	 */
	public static final class Builder extends AbstractBuilder<DefaultOAuth2TokenContext, Builder> {

		private Builder() {
		}

		/**
		 * Builds a new {@link DefaultOAuth2TokenContext}.
		 * @return the {@link DefaultOAuth2TokenContext}
		 */
		@Override
		public DefaultOAuth2TokenContext build() {
			return new DefaultOAuth2TokenContext(getContext());
		}

	}

}
