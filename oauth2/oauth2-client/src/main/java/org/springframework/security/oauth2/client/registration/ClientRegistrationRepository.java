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
package org.springframework.security.oauth2.client.registration;

import java.util.List;

/**
 * Implementations of this interface are responsible for the management of {@link ClientRegistration}'s.
 *
 * <p>
 * The <i>primary</i> client registration information is stored with the associated <i>Authorization Server</i>.
 * However, there may be uses cases where <i>secondary</i> information may need to be managed
 * that is not supported (or provided) by the <i>Authorization Server</i>.
 * This interface provides this capability for managing the <i>primary</i> and <i>secondary</i>
 * information of a client registration.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see ClientRegistration
 */
public interface ClientRegistrationRepository {

	ClientRegistration getRegistrationByClientId(String clientId);

	ClientRegistration getRegistrationByClientAlias(String clientAlias);

	List<ClientRegistration> getRegistrations();

}
