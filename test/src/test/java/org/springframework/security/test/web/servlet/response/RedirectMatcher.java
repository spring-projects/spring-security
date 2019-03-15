/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.test.web.servlet.response;

import static org.assertj.core.api.Assertions.assertThat;

import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultMatcher;

/**
 * Necessary to support binary compatibility for Spring IO Checks against Cario
 * since Spring Framework changed the signature in Spring 5. See
 * https://github.com/spring-projects/spring-framework/commit/
 * a795fd47142bd3b206ce244b94b1fd1dd0adc2e9
 *
 * @author Rob Winch
 */
public class RedirectMatcher {

	public static ResultMatcher redirectUrl(final String expectedUrl) {
		return new ResultMatcher() {

			@Override
			public void match(MvcResult result) throws Exception {
				assertThat(result.getResponse().getRedirectedUrl()).isEqualTo(expectedUrl);
			}
		};
	}
}
