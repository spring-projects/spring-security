/*
 * Copyright 2002-2021 the original author or authors.
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

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.TestSecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultHandler;

/**
 * Security related {@link MockMvc} {@link ResultHandler}s
 *
 * @author Marcus da Coregio
 * @since 5.6
 */
public final class SecurityMockMvcResultHandlers {

	private SecurityMockMvcResultHandlers() {
	}

	/**
	 * Exports the {@link SecurityContext} from {@link TestSecurityContextHolder} to
	 * {@link SecurityContextHolder}
	 */
	public static ResultHandler exportTestSecurityContext() {
		return new ExportTestSecurityContextHandler();
	}

	/**
	 * A {@link ResultHandler} that copies the {@link SecurityContext} from
	 * {@link TestSecurityContextHolder} to {@link SecurityContextHolder}
	 *
	 * @author Marcus da Coregio
	 * @since 5.6
	 */
	private static class ExportTestSecurityContextHandler implements ResultHandler {

		@Override
		public void handle(MvcResult result) {
			SecurityContextHolder.setContext(TestSecurityContextHolder.getContext());
		}

	}

}
