/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.access.vote;

import java.util.Collection;
import java.util.Iterator;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;

/**
 * Implementation of an {@link AccessDecisionVoter} for unit testing.
 * <p>
 * If the {@link ConfigAttribute#getAttribute()} has a value of <code>DENY_FOR_SURE</code>
 * , the voter will vote to deny access.
 * </p>
 * <p>
 * All comparisons are case sensitive.
 * </p>
 *
 * @author Ben Alex
 */
public class DenyVoter implements AccessDecisionVoter<Object> {

	public boolean supports(ConfigAttribute attribute) {
		if ("DENY_FOR_SURE".equals(attribute.getAttribute())) {
			return true;
		}
		else {
			return false;
		}
	}

	public boolean supports(Class<?> clazz) {
		return true;
	}

	public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {
		Iterator<ConfigAttribute> iter = attributes.iterator();

		while (iter.hasNext()) {
			ConfigAttribute attribute = iter.next();

			if (this.supports(attribute)) {
				return ACCESS_DENIED;
			}
		}

		return ACCESS_ABSTAIN;
	}

}
