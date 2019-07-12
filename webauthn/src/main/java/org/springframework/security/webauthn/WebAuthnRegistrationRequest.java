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

package org.springframework.security.webauthn;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;

public class WebAuthnRegistrationRequest {

	private HttpServletRequest httpServletRequest;
	private String clientDataBase64Url;
	private String attestationObjectBase64Url;
	private Set<String> transports;
	private String clientExtensionsJSON;

	public WebAuthnRegistrationRequest(
			HttpServletRequest httpServletRequest,
			String clientDataBase64Url,
			String attestationObjectBase64Url,
			Set<String> transports,
			String clientExtensionsJSON) {
		this.httpServletRequest = httpServletRequest;
		this.clientDataBase64Url = clientDataBase64Url;
		this.attestationObjectBase64Url = attestationObjectBase64Url;
		this.transports = transports == null ? null : Collections.unmodifiableSet(transports);
		this.clientExtensionsJSON = clientExtensionsJSON;
	}

	public HttpServletRequest getHttpServletRequest() {
		return httpServletRequest;
	}

	public String getClientDataBase64Url() {
		return clientDataBase64Url;
	}

	public String getAttestationObjectBase64Url() {
		return attestationObjectBase64Url;
	}

	public Set<String> getTransports() {
		return transports;
	}

	public String getClientExtensionsJSON() {
		return clientExtensionsJSON;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		WebAuthnRegistrationRequest that = (WebAuthnRegistrationRequest) o;
		return Objects.equals(httpServletRequest, that.httpServletRequest) &&
				Objects.equals(clientDataBase64Url, that.clientDataBase64Url) &&
				Objects.equals(attestationObjectBase64Url, that.attestationObjectBase64Url) &&
				Objects.equals(transports, that.transports) &&
				Objects.equals(clientExtensionsJSON, that.clientExtensionsJSON);
	}

	@Override
	public int hashCode() {
		return Objects.hash(httpServletRequest, clientDataBase64Url, attestationObjectBase64Url, transports, clientExtensionsJSON);
	}
}
