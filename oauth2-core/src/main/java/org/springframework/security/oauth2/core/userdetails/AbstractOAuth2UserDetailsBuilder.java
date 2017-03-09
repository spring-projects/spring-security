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
package org.springframework.security.oauth2.core.userdetails;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import java.util.*;
import java.util.stream.Collectors;

/**
 * @author Joe Grandja
 */
public abstract class AbstractOAuth2UserDetailsBuilder<O extends OAuth2UserDetails> {
	private static final String DEFAULT_IDENTIFIER_ATTRIBUTE_NAME = "id";
	private String identifierAttributeName = DEFAULT_IDENTIFIER_ATTRIBUTE_NAME;
	private Map<String, Object> userAttributes;

	protected AbstractOAuth2UserDetailsBuilder() {
	}

	public final AbstractOAuth2UserDetailsBuilder<O> userAttributes(Map<String, Object> userAttributes) {
		Assert.notEmpty(userAttributes, "userAttributes cannot be empty");
		this.userAttributes = userAttributes;
		return this;
	}

	public final AbstractOAuth2UserDetailsBuilder<O> identifierAttributeName(String identifierAttributeName) {
		Assert.notNull(identifierAttributeName, "identifierAttributeName cannot be null");
		this.identifierAttributeName = identifierAttributeName;
		return this;
	}

	public abstract O build();

	protected final List<OAuth2UserAttribute> getUserAttributes() {
		List<OAuth2UserAttribute> userAttributes = this.userAttributes.entrySet().stream()
				.map(e -> new OAuth2UserAttribute(e.getKey(), e.getValue())).collect(Collectors.toList());
		return userAttributes;
	}

	protected final OAuth2UserAttribute findIdentifier(List<OAuth2UserAttribute> userAttributes) {
		Optional<OAuth2UserAttribute> identifierAttribute = userAttributes.stream()
				.filter(e -> e.getName().equalsIgnoreCase(this.identifierAttributeName)).findFirst();
		Assert.isTrue(identifierAttribute.isPresent(), "Unable to find identifier attribute '" +
				this.identifierAttributeName + "' while attempting to build the OAuth2UserDetails");
		return identifierAttribute.get();
	}

	protected Set<GrantedAuthority> loadAuthorities(OAuth2UserAttribute identifierAttribute) {
		Set<GrantedAuthority> authorities = Collections.emptySet();

		// TODO Load authorities - see MappableAttributesRetriever and Attributes2GrantedAuthoritiesMapper

		return authorities;
	}
}