/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.webauthn.server;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;

import javax.servlet.ServletRequest;
import java.io.Serializable;
import java.net.URI;
import java.util.Objects;

/**
 * {@link WebAuthnOrigin} contains the fully qualified origin of the requester, as provided to the authenticator
 * by the client.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#dom-collectedclientdata-origin">5.10.1. Client Data Used in WebAuthn Signatures - origin</a>
 */
public class WebAuthnOrigin implements Serializable {

	private static final String SCHEME_HTTPS = "https";
	private static final String SCHEME_HTTP = "http";
	private static final String SCHEME_ERROR_MESSAGE = "scheme must be 'http' or 'https'";

	private String scheme;
	private String host;
	private int port;

	public WebAuthnOrigin(String scheme, String host, int port) {
		if (!Objects.equals(SCHEME_HTTPS, scheme) && !Objects.equals(SCHEME_HTTP, scheme)) {
			throw new IllegalArgumentException(SCHEME_ERROR_MESSAGE);
		}

		this.scheme = scheme;
		this.host = host;
		this.port = port;
	}

	public WebAuthnOrigin(String originUrl) {
		URI uri = URI.create(originUrl);
		this.scheme = uri.getScheme();
		this.host = uri.getHost();
		int originPort = uri.getPort();

		if (originPort == -1) {
			if (this.scheme == null) {
				throw new IllegalArgumentException(SCHEME_ERROR_MESSAGE);
			}
			switch (this.scheme) {
				case SCHEME_HTTPS:
					originPort = 443;
					break;
				case SCHEME_HTTP:
					originPort = 80;
					break;
				default:
					throw new IllegalArgumentException(SCHEME_ERROR_MESSAGE);
			}
		}
		this.port = originPort;
	}

	public static WebAuthnOrigin create(ServletRequest request) {
		return new WebAuthnOrigin(request.getScheme(), request.getServerName(), request.getServerPort());
	}

	public static WebAuthnOrigin create(String value) {
		try {
			return new WebAuthnOrigin(value);
		} catch (IllegalArgumentException e) {
			throw new IllegalArgumentException("value is out of range: " + e.getMessage());
		}
	}

	@JsonCreator
	private static WebAuthnOrigin deserialize(String value) throws InvalidFormatException {
		try {
			return create(value);
		} catch (IllegalArgumentException e) {
			throw new InvalidFormatException(null, "value is out of range", value, WebAuthnOrigin.class);
		}
	}

	public String getScheme() {
		return scheme;
	}

	public String getHost() {
		return host;
	}

	public int getPort() {
		return port;
	}

	@JsonValue
	@Override
	public String toString() {
		String result = this.scheme + "://" + this.host;
		switch (this.scheme) {
			case SCHEME_HTTPS:
				if (this.port != 443) {
					result += ":" + this.port;
				}
				break;
			case SCHEME_HTTP:
				if (this.port != 80) {
					result += ":" + this.port;
				}
				break;
			default:
				throw new IllegalStateException();
		}
		return result;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof WebAuthnOrigin)) return false;

		WebAuthnOrigin origin = (WebAuthnOrigin) o;

		if (port != origin.port) return false;
		//noinspection SimplifiableIfStatement
		if (!scheme.equals(origin.scheme)) return false;
		return host.equals(origin.host);
	}

	@Override
	public int hashCode() {
		int result = scheme.hashCode();
		result = 31 * result + host.hashCode();
		result = 31 * result + port;
		return result;
	}
}
