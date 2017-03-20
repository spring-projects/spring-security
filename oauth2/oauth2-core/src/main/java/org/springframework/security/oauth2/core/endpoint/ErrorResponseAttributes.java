/*
 * Copyright 2012-2017 the original author or authors.
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
package org.springframework.security.oauth2.core.endpoint;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.util.Assert;

/**
 * A representation of an <i>OAuth 2.0 Error Response</i>.
 *
 * <p>
 * An error response may be returned from either of the following locations:
 * <ul>
 * <li><a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.2.1">Section 4.1.2.1</a> Authorization Code Grant Response</li>
 * <li><a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.2.2.1">Section 4.2.2.1</a> Implicit Grant Response</li>
 * <li><a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-5.2">Section 5.2</a> Access Token Response</li>
 * <li><a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-7.2">Section 7.2</a> Protected Resource Response</li>
 * </ul>
 *
 * @author Joe Grandja
 * @since 5.0
 */
public final class ErrorResponseAttributes {
	private OAuth2Error errorObject;
	private String state;

	private ErrorResponseAttributes() {
	}

	public String getErrorCode() {
		return this.errorObject.getErrorCode();
	}

	public String getDescription() {
		return this.errorObject.getDescription();
	}

	public String getUri() {
		return this.errorObject.getUri();
	}

	public String getState() {
		return this.state;
	}

	public static Builder withErrorCode(String errorCode) {
		return new Builder(errorCode);
	}

	public static class Builder {
		private String errorCode;
		private String description;
		private String uri;
		private String state;

		private Builder(String errorCode) {
			Assert.hasText(errorCode, "errorCode cannot be empty");
			this.errorCode = errorCode;
		}

		public Builder description(String description) {
			this.description = description;
			return this;
		}

		public Builder uri(String uri) {
			this.uri = uri;
			return this;
		}

		public Builder state(String state) {
			this.state = state;
			return this;
		}

		public ErrorResponseAttributes build() {
			ErrorResponseAttributes errorResponse = new ErrorResponseAttributes();
			errorResponse.errorObject = new OAuth2Error(this.errorCode, this.description, this.uri);
			errorResponse.state = this.state;
			return errorResponse;
		}
	}
}
