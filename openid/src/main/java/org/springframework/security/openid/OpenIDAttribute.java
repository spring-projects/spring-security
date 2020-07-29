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

package org.springframework.security.openid;

import java.io.Serializable;
import java.util.List;

import org.springframework.util.Assert;

/**
 * Represents an OpenID subject identity attribute.
 * <p>
 * Can be used for configuring the <tt>OpenID4JavaConsumer</tt> with the attributes which
 * should be requested during a fetch request, or to hold values for an attribute which
 * are returned during the authentication process.
 *
 * @author Luke Taylor
 * @since 3.0
 * @deprecated The OpenID 1.0 and 2.0 protocols have been deprecated and users are
 * <a href="https://openid.net/specs/openid-connect-migration-1_0.html">encouraged to
 * migrate</a> to <a href="https://openid.net/connect/">OpenID Connect</a>, which is
 * supported by <code>spring-security-oauth2</code>.
 */
@Deprecated
public class OpenIDAttribute implements Serializable {

	private final String name;

	private final String typeIdentifier;

	private boolean required = false;

	private int count = 1;

	private final List<String> values;

	public OpenIDAttribute(String name, String type) {
		this.name = name;
		this.typeIdentifier = type;
		this.values = null;
	}

	public OpenIDAttribute(String name, String type, List<String> values) {
		Assert.notEmpty(values, "values cannot be empty");
		this.name = name;
		this.typeIdentifier = type;
		this.values = values;
	}

	/**
	 * The attribute name
	 */
	public String getName() {
		return this.name;
	}

	/**
	 * The attribute type Identifier (a URI).
	 */
	public String getType() {
		return this.typeIdentifier;
	}

	/**
	 * The "required" flag for the attribute when used with an authentication request.
	 * Defaults to "false".
	 */
	public boolean isRequired() {
		return this.required;
	}

	public void setRequired(boolean required) {
		this.required = required;
	}

	/**
	 * The requested count for the attribute when it is used as part of an authentication
	 * request. Defaults to 1.
	 */
	public int getCount() {
		return this.count;
	}

	public void setCount(int count) {
		this.count = count;
	}

	/**
	 * The values obtained from an attribute exchange.
	 */
	public List<String> getValues() {
		Assert.notNull(this.values, "Cannot read values from an authentication request attribute");
		return this.values;
	}

	@Override
	public String toString() {
		StringBuilder result = new StringBuilder("[");
		result.append(this.name);
		if (this.values != null) {
			result.append(":");
			result.append(this.values.toString());
		}
		result.append("]");
		return result.toString();
	}

}
