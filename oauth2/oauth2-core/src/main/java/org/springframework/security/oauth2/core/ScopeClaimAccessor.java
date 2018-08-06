/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.core;

import java.util.Collection;

/**
 * @author Josh Cummings
 * @since 5.1
 */
public interface ScopeClaimAccessor extends ClaimAccessor {
	/**
	 * Retrieve the scope attribute by {@code scopeClaimName} as a collection of individual scopes
	 *
	 * @param scopeClaimName
	 * @return the scope attribute as a collection of individual scopes
	 */
	default Collection<String> getScope(String scopeClaimName) {
		return this.getClaimAsStringCollection(scopeClaimName, " ");
	}
}
