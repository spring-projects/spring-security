/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.web.webauthn.api;

/**
 * <a href=
 * "https://www.w3.org/TR/webauthn-3/#enumdef-userverificationrequirement">UserVerificationRequirement</a>
 * is used by the Relying Party to indicate if user verification is needed.
 *
 * @author Rob Winch
 * @since 6.4
 */
public final class UserVerificationRequirement {

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#dom-userverificationrequirement-discouraged">discouraged</a>
	 * value indicates that the Relying Party does not want user verification employed
	 * during the operation (e.g., in the interest of minimizing disruption to the user
	 * interaction flow).
	 */
	public static final UserVerificationRequirement DISCOURAGED = new UserVerificationRequirement("discouraged");

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#dom-userverificationrequirement-preferred">preferred</a>
	 * value indicates that the Relying Party prefers user verification for the operation
	 * if possible, but will not fail the operation if the response does not have the UV
	 * flag set.
	 */
	public static final UserVerificationRequirement PREFERRED = new UserVerificationRequirement("preferred");

	/**
	 * The <a href=
	 * "https://www.w3.org/TR/webauthn-3/#dom-userverificationrequirement-required">required</a>
	 * value indicates that the Relying Party requires user verification for the operation
	 * and will fail the overall ceremony if the response does not have the UV flag set.
	 */
	public static final UserVerificationRequirement REQUIRED = new UserVerificationRequirement("required");

	private final String value;

	UserVerificationRequirement(String value) {
		this.value = value;
	}

	/**
	 * Gets the value
	 * @return the value
	 */
	public String getValue() {
		return this.value;
	}

}
