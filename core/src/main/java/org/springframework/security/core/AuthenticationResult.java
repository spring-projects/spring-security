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

package org.springframework.security.core;

import java.io.Serial;
import java.util.Collection;
import java.util.HashSet;
import java.util.function.Consumer;

import org.jspecify.annotations.NullMarked;

@NullMarked
public interface AuthenticationResult extends Authentication {

	@Serial
	long serialVersionUID = -525010730472051621L;

	default AuthenticationResult withGrantedAuthorities(Consumer<Collection<GrantedAuthority>> consumer) {
		Collection<GrantedAuthority> existing = new HashSet<>(getAuthorities());
		consumer.accept(existing);
		return withGrantedAuthorities(existing);
	}

	AuthenticationResult withGrantedAuthorities(Collection<GrantedAuthority> authorities);

	default boolean isAuthenticated() {
		return true;
	}

}
