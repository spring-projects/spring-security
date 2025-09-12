/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.docs.features.integrations.rest.type;

import org.springframework.security.docs.features.integrations.rest.clientregistrationid.User;
import org.springframework.security.oauth2.client.annotation.ClientRegistrationId;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.HttpExchange;

/**
 * Demonstrates a service for {@link ClientRegistrationId} at the type level.
 * @author Rob Winch
 */
// tag::type[]
@HttpExchange
@ClientRegistrationId("github")
public interface UserService {

	@GetExchange("/user")
	User getAuthenticatedUser();

	@GetExchange("/users/{username}/hovercard")
	Hovercard getHovercard(@PathVariable String username);

}
// end::type[]
