/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.web.authentication.ott;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;

/**
 * A strategy for resolving a {@link GenerateOneTimeTokenRequest} from the
 * {@link HttpServletRequest}.
 *
 * @author Max Batischev
 * @since 6.5
 */
public interface GenerateOneTimeTokenRequestResolver {

	/**
	 * Resolves {@link GenerateOneTimeTokenRequest} from {@link HttpServletRequest}
	 * @param request {@link HttpServletRequest} to resolve
	 * @return {@link GenerateOneTimeTokenRequest}
	 */
	@Nullable
	GenerateOneTimeTokenRequest resolve(HttpServletRequest request);

}
