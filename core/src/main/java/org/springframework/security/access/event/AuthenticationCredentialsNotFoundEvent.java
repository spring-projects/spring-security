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

package org.springframework.security.access.event;

import java.util.Collection;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.util.Assert;

/**
 * Indicates a secure object invocation failed because the <code>Authentication</code>
 * could not be obtained from the <code>SecurityContextHolder</code>.
 *
 * @author Ben Alex
 */
public class AuthenticationCredentialsNotFoundEvent extends AbstractAuthorizationEvent {

	private final AuthenticationCredentialsNotFoundException credentialsNotFoundException;

	private final Collection<ConfigAttribute> configAttribs;

	/**
	 * Construct the event.
	 * @param secureObject the secure object
	 * @param attributes that apply to the secure object
	 * @param credentialsNotFoundException exception returned to the caller (contains
	 * reason)
	 *
	 */
	public AuthenticationCredentialsNotFoundEvent(Object secureObject, Collection<ConfigAttribute> attributes,
			AuthenticationCredentialsNotFoundException credentialsNotFoundException) {
		super(secureObject);
		Assert.isTrue(attributes != null && credentialsNotFoundException != null,
				"All parameters are required and cannot be null");
		this.configAttribs = attributes;
		this.credentialsNotFoundException = credentialsNotFoundException;
	}

	public Collection<ConfigAttribute> getConfigAttributes() {
		return this.configAttribs;
	}

	public AuthenticationCredentialsNotFoundException getCredentialsNotFoundException() {
		return this.credentialsNotFoundException;
	}

}
