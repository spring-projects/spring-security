/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.core.authority.mapping;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;

/**
 * Interface to be implemented by classes that can map a list of security attributes (such
 * as roles or group names) to a collection of Spring Security {@code GrantedAuthority}s.
 *
 * @author Ruud Senden
 * @since 2.0
 */
public interface Attributes2GrantedAuthoritiesMapper {

	/**
	 * Implementations of this method should map the given collection of attributes to a
	 * collection of Spring Security GrantedAuthorities. There are no restrictions for the
	 * mapping process; a single attribute can be mapped to multiple Spring Security
	 * GrantedAuthorities, all attributes can be mapped to a single Spring Security
	 * {@code GrantedAuthority}, some attributes may not be mapped, etc.
	 * @param attributes the attributes to be mapped
	 * @return the collection of authorities created from the attributes
	 */
	Collection<? extends GrantedAuthority> getGrantedAuthorities(Collection<String> attributes);

}
