/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.oauth2.client.userinfo;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

/**
 * A strategy for retrieving the user attributes
 * of the <i>End-User</i> (Resource Owner) from the <i>UserInfo Endpoint</i>
 * using the provided {@link OAuth2UserRequest#getAccessToken() Access Token}.
 *
 * @author Joe Grandja
 * @author Rob Winch
 * @since 5.0
 * @see OAuth2UserRequest
 * @see OAuth2UserService
 */
public interface UserInfoRetriever {

	<T> T retrieve(OAuth2UserRequest userRequest, Class<T> responseType) throws OAuth2AuthenticationException;

}
