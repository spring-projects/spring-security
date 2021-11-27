/*
 * Copyright 2012-2019 the original author or authors.
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

package org.springframework.security.web.util.matcher;

import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

/**
 * An interface for extracting URI variables from the {@link HttpServletRequest}.
 *
 * @author Rob Winch
 * @since 4.1.1
 * @deprecated use {@link RequestMatcher.MatchResult} from
 * {@link RequestMatcher#matcher(HttpServletRequest)}
 */
@Deprecated
public interface RequestVariablesExtractor {

	/**
	 * Extract URL template variables from the request.
	 * @param request the HttpServletRequest to obtain a URL to extract the variables from
	 * @return the URL variables or empty if no variables are found
	 */
	Map<String, String> extractUriTemplateVariables(HttpServletRequest request);

}
