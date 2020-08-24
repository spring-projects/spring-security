/*
 * Copyright 2015-2016 the original author or authors.
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

package org.springframework.security.cas.jackson2;

import java.util.Collection;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import org.jasig.cas.client.validation.Assertion;

import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Mixin class which helps in deserialize
 * {@link org.springframework.security.cas.authentication.CasAuthenticationToken} using
 * jackson. Two more dependent classes needs to register along with this mixin class.
 * <ol>
 * <li>{@link org.springframework.security.cas.jackson2.AssertionImplMixin}</li>
 * <li>{@link org.springframework.security.cas.jackson2.AttributePrincipalImplMixin}</li>
 * </ol>
 *
 * <p>
 *
 * <pre>
 *     ObjectMapper mapper = new ObjectMapper();
 *     mapper.registerModule(new CasJackson2Module());
 * </pre>
 *
 * @author Jitendra Singh
 * @see CasJackson2Module
 * @see org.springframework.security.jackson2.SecurityJackson2Modules
 * @since 4.2
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, isGetterVisibility = JsonAutoDetect.Visibility.NONE,
		getterVisibility = JsonAutoDetect.Visibility.NONE, creatorVisibility = JsonAutoDetect.Visibility.ANY)
@JsonIgnoreProperties(ignoreUnknown = true)
class CasAuthenticationTokenMixin {

	/**
	 * Mixin Constructor helps in deserialize {@link CasAuthenticationToken}
	 * @param keyHash hashCode of provided key to identify if this object made by a given
	 * {@link CasAuthenticationProvider}
	 * @param principal typically the UserDetails object (cannot be <code>null</code>)
	 * @param credentials the service/proxy ticket ID from CAS (cannot be
	 * <code>null</code>)
	 * @param authorities the authorities granted to the user (from the
	 * {@link org.springframework.security.core.userdetails.UserDetailsService}) (cannot
	 * be <code>null</code>)
	 * @param userDetails the user details (from the
	 * {@link org.springframework.security.core.userdetails.UserDetailsService}) (cannot
	 * be <code>null</code>)
	 * @param assertion the assertion returned from the CAS servers. It contains the
	 * principal and how to obtain a proxy ticket for the user.
	 */
	@JsonCreator
	CasAuthenticationTokenMixin(@JsonProperty("keyHash") Integer keyHash, @JsonProperty("principal") Object principal,
			@JsonProperty("credentials") Object credentials,
			@JsonProperty("authorities") Collection<? extends GrantedAuthority> authorities,
			@JsonProperty("userDetails") UserDetails userDetails, @JsonProperty("assertion") Assertion assertion) {
	}

}
