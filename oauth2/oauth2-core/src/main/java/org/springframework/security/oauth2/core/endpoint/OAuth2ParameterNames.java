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
package org.springframework.security.oauth2.core.endpoint;

/**
 * Standard and additional (custom) parameter names defined in the OAuth Parameters Registry
 * and used by the authorization endpoint and token endpoint.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-11.2">11.2 OAuth Parameters Registry</a>
 */
public interface OAuth2ParameterNames {

	String RESPONSE_TYPE = "response_type";

	String CLIENT_ID = "client_id";

	String REDIRECT_URI = "redirect_uri";

	String SCOPE = "scope";

	String STATE = "state";

	String CODE = "code";

	String ERROR = "error";

	String ERROR_DESCRIPTION = "error_description";

	String ERROR_URI = "error_uri";

	String REGISTRATION_ID = "registration_id";		// Non-standard additional parameter

}
