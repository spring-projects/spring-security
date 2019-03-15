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

import java.util.Set;

/**
 * Interface to be implemented by classes that can retrieve a list of mappable security
 * attribute strings (for example the list of all available J2EE roles in a web or EJB
 * application).
 *
 * @author Ruud Senden
 * @since 2.0
 */
public interface MappableAttributesRetriever {
	/**
	 * Implementations of this method should return a set of all string attributes which
	 * can be mapped to <tt>GrantedAuthority</tt>s.
	 *
	 * @return set of all mappable roles
	 */
	Set<String> getMappableAttributes();
}
