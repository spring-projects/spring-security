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
package org.springframework.security.acls.domain;

import org.springframework.security.acls.model.Permission;

/**
 * Provides an abstract superclass for {@link Permission} implementations.
 *
 * @author Ben Alex
 * @since 2.0.3
 */
public abstract class AbstractPermission implements Permission {

	protected final char code;

	protected int mask;

	/**
	 * Sets the permission mask and uses the '*' character to represent active bits when
	 * represented as a bit pattern string.
	 * @param mask the integer bit mask for the permission
	 */
	protected AbstractPermission(int mask) {
		this.mask = mask;
		this.code = '*';
	}

	/**
	 * Sets the permission mask and uses the specified character for active bits.
	 * @param mask the integer bit mask for the permission
	 * @param code the character to print for each active bit in the mask (see
	 * {@link Permission#getPattern()})
	 */
	protected AbstractPermission(int mask, char code) {
		this.mask = mask;
		this.code = code;
	}

	@Override
	public final boolean equals(Object arg0) {
		if (arg0 == null) {
			return false;
		}

		if (!(arg0 instanceof Permission)) {
			return false;
		}

		Permission rhs = (Permission) arg0;

		return (this.mask == rhs.getMask());
	}

	@Override
	public final int getMask() {
		return this.mask;
	}

	@Override
	public String getPattern() {
		return AclFormattingUtils.printBinary(this.mask, this.code);
	}

	@Override
	public final String toString() {
		return this.getClass().getSimpleName() + "[" + getPattern() + "=" + this.mask + "]";
	}

	@Override
	public final int hashCode() {
		return this.mask;
	}

}
