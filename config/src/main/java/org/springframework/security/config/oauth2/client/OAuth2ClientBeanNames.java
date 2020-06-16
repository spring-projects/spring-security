/*
 * Copyright 2002-2020 the original author or authors.
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
package org.springframework.security.config.oauth2.client;

import org.springframework.context.annotation.Bean;

/**
 * {@link Bean} names used (reserved) for OAuth 2.0 Client support.
 *
 * @author Joe Grandja
 * @since 5.4
 */
public interface OAuth2ClientBeanNames {

	String REST_OPERATIONS = "org.springframework.security.oauth2.client.restOperations";

	String DEFAULT_OAUTH2_AUTHORIZED_CLIENT_MANAGER = "org.springframework.security.oauth2.client.defaultOAuth2AuthorizedClientManager";

}
