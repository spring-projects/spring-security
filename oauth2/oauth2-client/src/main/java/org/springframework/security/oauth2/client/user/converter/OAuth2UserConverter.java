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
package org.springframework.security.oauth2.client.user.converter;

import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.Assert;

import java.util.Map;

/**
 *
 * @author Joe Grandja
 * @since 5.0
 */
public final class OAuth2UserConverter extends AbstractOAuth2UserConverter<OAuth2User> {
	private final String nameAttributeKey;

	public OAuth2UserConverter(String nameAttributeKey) {
		Assert.hasText(nameAttributeKey, "nameAttributeKey cannot be empty");
		this.nameAttributeKey = nameAttributeKey;
	}

	@Override
	protected OAuth2User convert(Map<String, Object> userAttributes) {
		return new DefaultOAuth2User(userAttributes, this.nameAttributeKey);
	}
}
