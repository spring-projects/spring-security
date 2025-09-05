/*
 * Copyright 2020-2021 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.client;

import org.springframework.lang.Nullable;

/**
 * A repository for OAuth 2.0 {@link RegisteredClient}(s).
 *
 * @author Joe Grandja
 * @author Anoop Garlapati
 * @author Ovidiu Popa
 * @since 0.0.1
 * @see RegisteredClient
 */
public interface RegisteredClientRepository {

	/**
	 * Saves the registered client.
	 *
	 * <p>
	 * IMPORTANT: Sensitive information should be encoded externally from the
	 * implementation, e.g. {@link RegisteredClient#getClientSecret()}
	 * @param registeredClient the {@link RegisteredClient}
	 */
	void save(RegisteredClient registeredClient);

	/**
	 * Returns the registered client identified by the provided {@code id}, or
	 * {@code null} if not found.
	 * @param id the registration identifier
	 * @return the {@link RegisteredClient} if found, otherwise {@code null}
	 */
	@Nullable
	RegisteredClient findById(String id);

	/**
	 * Returns the registered client identified by the provided {@code clientId}, or
	 * {@code null} if not found.
	 * @param clientId the client identifier
	 * @return the {@link RegisteredClient} if found, otherwise {@code null}
	 */
	@Nullable
	RegisteredClient findByClientId(String clientId);

}
