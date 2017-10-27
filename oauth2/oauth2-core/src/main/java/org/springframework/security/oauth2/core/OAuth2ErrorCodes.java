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
package org.springframework.security.oauth2.core;

/**
 * Standard error codes defined by the <i>OAuth 2.0 Authorization Framework</i>.
 *
 * @author Joe Grandja
 * @since 5.0
 */
public interface OAuth2ErrorCodes {

	String INVALID_REQUEST = "invalid_request";

	String UNAUTHORIZED_CLIENT = "unauthorized_client";

	String ACCESS_DENIED = "access_denied";

	String UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type";

	String INVALID_SCOPE = "invalid_scope";

	String SERVER_ERROR = "server_error";

	String TEMPORARILY_UNAVAILABLE = "temporarily_unavailable";

	String INVALID_CLIENT = "invalid_client";

	String INVALID_GRANT = "invalid_grant";

	String UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type";

}
