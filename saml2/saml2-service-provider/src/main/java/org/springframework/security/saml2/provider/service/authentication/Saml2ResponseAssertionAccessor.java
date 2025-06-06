/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.saml2.provider.service.authentication;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

import org.jspecify.annotations.Nullable;

import org.springframework.util.CollectionUtils;

/**
 * An interface that represents key details from a SAML 2.0 Assertion
 *
 * @author Josh Cummings
 * @since 7.0
 * @see Saml2ResponseAssertion
 */
public interface Saml2ResponseAssertionAccessor extends Serializable {

	String getNameId();

	List<String> getSessionIndexes();

	/**
	 * Get the first value of Saml2 token attribute by name
	 * @param name the name of the attribute
	 * @param <A> the type of the attribute
	 * @return the first attribute value or {@code null} otherwise
	 */
	@Nullable default <A> A getFirstAttribute(String name) {
		List<A> values = getAttribute(name);
		return CollectionUtils.firstElement(values);
	}

	/**
	 * Get the Saml2 token attribute by name
	 * @param name the name of the attribute
	 * @param <A> the type of the attribute
	 * @return the attribute or {@code null} otherwise
	 */
	@Nullable default <A> List<A> getAttribute(String name) {
		return (List<A>) getAttributes().get(name);
	}

	Map<String, List<Object>> getAttributes();

	String getResponseValue();

}
