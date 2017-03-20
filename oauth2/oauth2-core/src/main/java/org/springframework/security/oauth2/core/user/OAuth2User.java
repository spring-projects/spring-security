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
package org.springframework.security.oauth2.core.user;

import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serializable;
import java.util.Collection;
import java.util.Map;

/**
 * A representation of a user <code>Principal</code>
 * that is registered with a standard <i>OAuth 2.0 Provider</i>.
 *
 * <p>
 * An OAuth 2.0 user is composed of one or more attributes, for example,
 * first name, middle name, last name, email, phone number, address, etc.
 * Each user attribute has a &quot;name&quot; and &quot;value&quot; and
 * is keyed by the &quot;name&quot; in {@link #getAttributes()}.
 *
 * <p>
 * <b>NOTE:</b> Attribute names are <b><i>not</i></b> standardized between providers and therefore will vary.
 * Please consult the provider's API documentation for the set of supported user attribute names.
 *
 * <p>
 * Implementation instances of this interface represent an {@link AuthenticatedPrincipal}
 * which is associated to an {@link Authentication} object
 * and may be accessed via {@link Authentication#getPrincipal()}.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see DefaultOAuth2User
 * @see AuthenticatedPrincipal
 */
public interface OAuth2User extends AuthenticatedPrincipal, Serializable {

	Collection<? extends GrantedAuthority> getAuthorities();

	Map<String, Object> getAttributes();
}
