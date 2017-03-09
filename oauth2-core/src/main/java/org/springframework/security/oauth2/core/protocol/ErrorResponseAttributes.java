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
package org.springframework.security.oauth2.core.protocol;

import org.springframework.util.Assert;

import java.net.URI;

/**
 * @author Joe Grandja
 */
public class ErrorResponseAttributes {
	private final String errorCode;
	private final String errorDescription;
	private final URI errorUri;
	private final String state;

	public ErrorResponseAttributes(String errorCode) {
		this(errorCode, null, null);
	}

	public ErrorResponseAttributes(String errorCode, String errorDescription, URI errorUri) {
		this(errorCode, errorDescription, errorUri, null);
	}

	public ErrorResponseAttributes(String errorCode, String errorDescription, URI errorUri, String state) {
		Assert.notNull(errorCode, "errorCode cannot be null");
		this.errorCode = errorCode;

		this.errorDescription = errorDescription;
		this.errorUri = errorUri;
		this.state = state;
	}

	public final String getErrorCode() {
		return this.errorCode;
	}

	public final String getErrorDescription() {
		return this.errorDescription;
	}

	public final URI getErrorUri() {
		return this.errorUri;
	}

	public final String getState() {
		return this.state;
	}
}