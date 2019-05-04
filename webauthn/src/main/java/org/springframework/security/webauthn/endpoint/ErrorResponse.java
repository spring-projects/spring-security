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

package org.springframework.security.webauthn.endpoint;

import java.util.Objects;

/**
 * Error response of {@link AttestationOptionsEndpointFilter}
 *
 * @author Yoshikazu Nojima
 */
public class ErrorResponse {

	// ~ Instance fields
	// ================================================================================================

	private String errorMessage;

	// ~ Constructor
	// ========================================================================================================

	public ErrorResponse(String errorMessage) {
		this.errorMessage = errorMessage;
	}

	// ~ Methods
	// ========================================================================================================

	public String getErrorMessage() {
		return errorMessage;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		ErrorResponse that = (ErrorResponse) o;
		return Objects.equals(errorMessage, that.errorMessage);
	}

	@Override
	public int hashCode() {
		return Objects.hash(errorMessage);
	}
}
