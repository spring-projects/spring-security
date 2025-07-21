/*
 * Copyright 2002-2025 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain clients copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.docs.features.integrations.rest.clientregistrationid;

import org.springframework.security.oauth2.client.annotation.ClientRegistrationId;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.HttpExchange;

/**
 * Demonstrates a service for {@link ClientRegistrationId} and HTTP Interface clients.
 * @author Rob Winch
 */
@HttpExchange
public interface UserService {

	// tag::getAuthenticatedUser[]
	@GetExchange("/user")
	@ClientRegistrationId("github")
	User getAuthenticatedUser();
	// end::getAuthenticatedUser[]

}
