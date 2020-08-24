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

package org.springframework.security.core.token;

import java.util.Date;

import org.springframework.util.Assert;

/**
 * The default implementation of {@link Token}.
 *
 * @author Ben Alex
 * @since 2.0.1
 */
public class DefaultToken implements Token {

	private final String key;

	private final long keyCreationTime;

	private final String extendedInformation;

	public DefaultToken(String key, long keyCreationTime, String extendedInformation) {
		Assert.hasText(key, "Key required");
		Assert.notNull(extendedInformation, "Extended information cannot be null");
		this.key = key;
		this.keyCreationTime = keyCreationTime;
		this.extendedInformation = extendedInformation;
	}

	@Override
	public String getKey() {
		return this.key;
	}

	@Override
	public long getKeyCreationTime() {
		return this.keyCreationTime;
	}

	@Override
	public String getExtendedInformation() {
		return this.extendedInformation;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj != null && obj instanceof DefaultToken) {
			DefaultToken rhs = (DefaultToken) obj;
			return this.key.equals(rhs.key) && this.keyCreationTime == rhs.keyCreationTime
					&& this.extendedInformation.equals(rhs.extendedInformation);
		}
		return false;
	}

	@Override
	public int hashCode() {
		int code = 979;
		code = code * this.key.hashCode();
		code = code * new Long(this.keyCreationTime).hashCode();
		code = code * this.extendedInformation.hashCode();
		return code;
	}

	@Override
	public String toString() {
		return "DefaultToken[key=" + this.key + "; creation=" + new Date(this.keyCreationTime) + "; extended="
				+ this.extendedInformation + "]";
	}

}
