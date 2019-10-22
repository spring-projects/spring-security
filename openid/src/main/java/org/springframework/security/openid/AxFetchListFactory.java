/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.openid;

import java.util.List;

/**
 * A strategy which can be used by an OpenID consumer implementation, to dynamically
 * determine the attribute exchange information based on the OpenID identifier.
 * <p>
 * This allows the list of attributes for a fetch request to be tailored for different
 * OpenID providers, since they do not all support the same attributes.
 *
 * @deprecated The OpenID 1.0 and 2.0 protocols have been deprecated and users are
 * <a href="https://openid.net/specs/openid-connect-migration-1_0.html">encouraged to migrate</a>
 * to <a href="https://openid.net/connect/">OpenID Connect</a>.
 * @author Luke Taylor
 * @since 3.1
 */
public interface AxFetchListFactory {

	/**
	 * Builds the list of attributes which should be added to the fetch request for the
	 * supplied OpenID identifier.
	 *
	 * @param identifier the claimed_identity
	 * @return the attributes to fetch for this identifier
	 */
	List<OpenIDAttribute> createAttributeList(String identifier);
}
