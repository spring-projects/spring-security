/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.saml2;

/**
 * @since 5.2
 */
public class Saml2Exception extends RuntimeException {

	public Saml2Exception(String message) {
		super(message);
	}

	public Saml2Exception(String message, Throwable cause) {
		super(message, cause);
	}

	public Saml2Exception(Throwable cause) {
		super(cause);
	}

}
