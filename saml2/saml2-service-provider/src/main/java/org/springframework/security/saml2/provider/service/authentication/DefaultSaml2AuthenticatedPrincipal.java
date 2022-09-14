/*
 * Copyright 2002-2022 the original author or authors.
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

import java.io.Serializable;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.springframework.util.Assert;

/**
 * Default implementation of a {@link Saml2AuthenticatedPrincipal}.
 *
 * @author Clement Stoquart
 * @since 5.4
 */
public class DefaultSaml2AuthenticatedPrincipal implements Saml2AuthenticatedPrincipal, Serializable {

	private final String name;

	private final Map<String, List<Object>> attributes;

	private final List<String> sessionIndexes;

	private String registrationId;

	public DefaultSaml2AuthenticatedPrincipal(String name, Map<String, List<Object>> attributes) {
		this(name, attributes, Collections.emptyList());
	}

	public DefaultSaml2AuthenticatedPrincipal(String name, Map<String, List<Object>> attributes,
			List<String> sessionIndexes) {
		Assert.notNull(name, "name cannot be null");
		Assert.notNull(attributes, "attributes cannot be null");
		Assert.notNull(sessionIndexes, "sessionIndexes cannot be null");
		this.name = name;
		this.attributes = attributes;
		this.sessionIndexes = sessionIndexes;
	}

	@Override
	public String getName() {
		return this.name;
	}

	@Override
	public Map<String, List<Object>> getAttributes() {
		return this.attributes;
	}

	@Override
	public List<String> getSessionIndexes() {
		return this.sessionIndexes;
	}

	@Override
	public String getRelyingPartyRegistrationId() {
		return this.registrationId;
	}

	public void setRelyingPartyRegistrationId(String registrationId) {
		Assert.notNull(registrationId, "relyingPartyRegistrationId cannot be null");
		this.registrationId = registrationId;
	}

}
