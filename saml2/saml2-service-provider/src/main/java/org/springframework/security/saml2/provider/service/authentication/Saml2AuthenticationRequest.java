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

package org.springframework.security.saml2.provider.service.authentication;

import org.springframework.security.saml2.credentials.Saml2X509Credential;
import org.springframework.util.Assert;

import java.util.LinkedList;
import java.util.List;

/**
 * Data holder for information required to send an {@code AuthNRequest}
 * from the service provider to the identity provider
 *
 * @see {@link Saml2AuthenticationRequestFactory}
 * @see https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf (line 2031)
 * @since 5.2
 */
public class Saml2AuthenticationRequest {
	private final String localSpEntityId;
	private final List<Saml2X509Credential> credentials;
	private String webSsoUri;

	public Saml2AuthenticationRequest(String localSpEntityId, String webSsoUri, List<Saml2X509Credential> credentials) {
		Assert.hasText(localSpEntityId, "localSpEntityId cannot be null");
		Assert.hasText(localSpEntityId, "webSsoUri cannot be null");
		this.localSpEntityId = localSpEntityId;
		this.webSsoUri = webSsoUri;
		this.credentials = new LinkedList<>();
		for (Saml2X509Credential c : credentials) {
			if (c.isSigningCredential()) {
				this.credentials.add(c);
			}
		}
		Assert.notEmpty(this.credentials, "at least one SIGNING credential must be present");
	}


	public String getLocalSpEntityId() {
		return this.localSpEntityId;
	}

	public String getWebSsoUri() {
		return this.webSsoUri;
	}

	public List<Saml2X509Credential> getCredentials() {
		return this.credentials;
	}
}
