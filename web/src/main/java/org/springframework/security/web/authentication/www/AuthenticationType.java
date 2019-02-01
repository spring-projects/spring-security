/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.web.authentication.www;

/**
 * This class represents a supported Authentication type, which can be `Basic`, `Digest` etc.
 *
 * @author Sergey Bespalov
 *
 * @see AuthenticationTypeParser
 */
public class AuthenticationType {

	private final String name;

	public AuthenticationType(String name) {
		if (name == null) {
			throw new NullPointerException("Authentication type name can not be null.");
		}

		this.name = name;
	}

	public String getName() {
		return name;
	}

	@Override
	public int hashCode() {
		return name.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof AuthenticationType)) {
			return false;
		}
		AuthenticationType other = (AuthenticationType) obj;
		return name.equals(other.name);
	}

	@Override
	public String toString() {
		return name;
	}

}
