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

import com.webauthn4j.util.Base64UrlUtil;
import org.springframework.security.webauthn.server.WebAuthnServerProperty;
import org.springframework.security.webauthn.server.WebAuthnServerPropertyProvider;
import org.springframework.util.Assert;

import java.util.List;

public class WebAuthnRegistrationRequestValidator {

	private WebAuthnManager webAuthnManager;
	private WebAuthnServerPropertyProvider webAuthnServerPropertyProvider;

	private List<String> expectedRegistrationExtensionIds;

	public WebAuthnRegistrationRequestValidator(
			WebAuthnManager webAuthnManager,
			WebAuthnServerPropertyProvider webAuthnServerPropertyProvider) {

		this.webAuthnManager = webAuthnManager;
		this.webAuthnServerPropertyProvider = webAuthnServerPropertyProvider;
	}

	public void validate(WebAuthnRegistrationRequest registrationRequest) {

		Assert.notNull(registrationRequest, "target must not be null");
		Assert.notNull(registrationRequest.getHttpServletRequest(), "httpServletRequest must not be null");

		WebAuthnServerProperty webAuthnServerProperty = webAuthnServerPropertyProvider.provide(registrationRequest.getHttpServletRequest());

		WebAuthnRegistrationData webAuthnRegistrationData = new WebAuthnRegistrationData(
				Base64UrlUtil.decode(registrationRequest.getClientDataBase64Url()),
				Base64UrlUtil.decode(registrationRequest.getAttestationObjectBase64Url()),
				registrationRequest.getTransports(),
				registrationRequest.getClientExtensionsJSON(),
				webAuthnServerProperty,
				expectedRegistrationExtensionIds);

		webAuthnManager.verifyRegistrationData(webAuthnRegistrationData);
	}

	public List<String> getExpectedRegistrationExtensionIds() {
		return expectedRegistrationExtensionIds;
	}

	public void setExpectedRegistrationExtensionIds(List<String> expectedRegistrationExtensionIds) {
		this.expectedRegistrationExtensionIds = expectedRegistrationExtensionIds;
	}

}
