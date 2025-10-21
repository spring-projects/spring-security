/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.web.authentication.preauth.websphere;

import java.util.List;

import org.jspecify.annotations.Nullable;

/**
 * Provides indirection between classes using websphere and the actual container
 * interaction, allowing for easier unit testing.
 * <p>
 * Only for internal use.
 *
 * @author Luke Taylor
 * @since 3.0.0
 */
interface WASUsernameAndGroupsExtractor {

	List<String> getGroupsForCurrentUser();

	@Nullable String getCurrentUserName();

}
