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
package org.springframework.security.openid.connect.core.userdetails;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.userdetails.AbstractOAuth2UserDetailsBuilder;
import org.springframework.security.oauth2.core.userdetails.OAuth2UserAttribute;
import org.springframework.security.openid.connect.core.OpenIDConnectAttributes;

import java.util.List;
import java.util.Set;

/**
 * @author Joe Grandja
 */
public class OpenIDConnectUserBuilder extends AbstractOAuth2UserDetailsBuilder<OpenIDConnectUser> {

	public OpenIDConnectUserBuilder() {
		this.identifierAttributeName(OpenIDConnectAttributes.Claim.SUB);
	}

	@Override
	public OpenIDConnectUser build() {
		List<OAuth2UserAttribute> userAttributes = this.getUserAttributes();
		OAuth2UserAttribute identifierAttribute = this.findIdentifier(userAttributes);
		Set<GrantedAuthority> authorities = this.loadAuthorities(identifierAttribute);
		return new OpenIDConnectUser(identifierAttribute, userAttributes, authorities);
	}
}