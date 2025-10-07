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

package org.springframework.security.authorization;

import java.util.List;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/**
 * Finds additional required authorities for the provided {@link Authentication#getName()}
 *
 * @author Rob Winch
 * @since 7.0
 */
public interface RequiredAuthoritiesRepository {

	/**
	 * Finds additional required {@link GrantedAuthority#getAuthority()}s for the provided
	 * username.
	 * @param username the username. Cannot be null or empty.
	 * @return the additional authorities required.
	 */
	List<String> findRequiredAuthorities(String username);

}
