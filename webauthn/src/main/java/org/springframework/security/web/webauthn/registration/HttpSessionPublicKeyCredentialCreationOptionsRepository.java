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

package org.springframework.security.web.webauthn.registration;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.util.Assert;

public class HttpSessionPublicKeyCredentialCreationOptionsRepository
		implements PublicKeyCredentialCreationOptionsRepository {

	static final String DEFAULT_ATTR_NAME = PublicKeyCredentialCreationOptions.class.getName().concat("ATTR_NAME");

	private String attrName = DEFAULT_ATTR_NAME;

	@Override
	public void save(HttpServletRequest request, HttpServletResponse response,
			PublicKeyCredentialCreationOptions options) {
		request.getSession().setAttribute(this.attrName, options);
	}

	public PublicKeyCredentialCreationOptions load(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		if (session == null) {
			return null;
		}
		return (PublicKeyCredentialCreationOptions) session.getAttribute(this.attrName);
	}

	public void setAttrName(String attrName) {
		Assert.notNull(attrName, "attrName cannot be null");
		this.attrName = attrName;
	}

}
