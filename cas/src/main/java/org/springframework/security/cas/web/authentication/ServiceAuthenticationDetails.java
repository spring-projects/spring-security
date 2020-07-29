/*
 * Copyright 2011-2016 the original author or authors.
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

package org.springframework.security.cas.web.authentication;

import java.io.Serializable;

import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.core.Authentication;

/**
 * In order for the {@link CasAuthenticationProvider} to provide the correct service url
 * to authenticate the ticket, the returned value of {@link Authentication#getDetails()}
 * should implement this interface when tickets can be sent to any URL rather than only
 * {@link ServiceProperties#getService()}.
 *
 * @author Rob Winch
 * @see ServiceAuthenticationDetailsSource
 */
public interface ServiceAuthenticationDetails extends Serializable {

	/**
	 * Gets the absolute service url (i.e. https://example.com/service/).
	 * @return the service url. Cannot be <code>null</code>.
	 */
	String getServiceUrl();

}
