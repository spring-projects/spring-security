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
package org.springframework.security.access.annotation;

import java.util.Collection;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/**
 * Voter on JSR-250 configuration attributes.
 *
 * @author Ryan Heaton
 * @since 2.0
 */
public class Jsr250Voter implements AccessDecisionVoter<Object> {

	/**
	 * The specified config attribute is supported if its an instance of a
	 * {@link Jsr250SecurityConfig}.
	 * @param configAttribute The config attribute.
	 * @return whether the config attribute is supported.
	 */
	@Override
	public boolean supports(ConfigAttribute configAttribute) {
		return configAttribute instanceof Jsr250SecurityConfig;
	}

	/**
	 * All classes are supported.
	 * @param clazz the class.
	 * @return true
	 */
	@Override
	public boolean supports(Class<?> clazz) {
		return true;
	}

	/**
	 * Votes according to JSR 250.
	 * <p>
	 * If no JSR-250 attributes are found, it will abstain, otherwise it will grant or
	 * deny access based on the attributes that are found.
	 * @param authentication The authentication object.
	 * @param object The access object.
	 * @param definition The configuration definition.
	 * @return The vote.
	 */
	@Override
	public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> definition) {
		boolean jsr250AttributeFound = false;

		for (ConfigAttribute attribute : definition) {
			if (Jsr250SecurityConfig.PERMIT_ALL_ATTRIBUTE.equals(attribute)) {
				return ACCESS_GRANTED;
			}

			if (Jsr250SecurityConfig.DENY_ALL_ATTRIBUTE.equals(attribute)) {
				return ACCESS_DENIED;
			}

			if (supports(attribute)) {
				jsr250AttributeFound = true;
				// Attempt to find a matching granted authority
				for (GrantedAuthority authority : authentication.getAuthorities()) {
					if (attribute.getAttribute().equals(authority.getAuthority())) {
						return ACCESS_GRANTED;
					}
				}
			}
		}

		return jsr250AttributeFound ? ACCESS_DENIED : ACCESS_ABSTAIN;
	}

}
