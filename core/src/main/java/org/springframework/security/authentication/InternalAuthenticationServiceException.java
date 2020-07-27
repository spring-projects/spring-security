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
package org.springframework.security.authentication;

/**
 * <p>
 * Thrown if an authentication request could not be processed due to a system problem that
 * occurred internally. It differs from {@link AuthenticationServiceException} in that it
 * would not be thrown if an external system has an internal error or failure. This
 * ensures that we can handle errors that are within our control distinctly from errors of
 * other systems. The advantage to this distinction is that the untrusted external system
 * should not be able to fill up logs and cause excessive IO. However, an internal system
 * should report errors.
 * </p>
 * <p>
 * This might be thrown if a backend authentication repository is unavailable, for
 * example. However, it would not be thrown in the event that an error occurred when
 * validating an OpenID response with an OpenID Provider.
 * </p>
 *
 * @author Rob Winch
 *
 */
public class InternalAuthenticationServiceException extends AuthenticationServiceException {

	public InternalAuthenticationServiceException(String message, Throwable cause) {
		super(message, cause);
	}

	public InternalAuthenticationServiceException(String message) {
		super(message);
	}

}
