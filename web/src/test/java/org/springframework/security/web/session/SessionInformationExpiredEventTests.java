/*
 * Copyright 2012-2016 the original author or authors.
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

package org.springframework.security.web.session;

import java.util.Date;

import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.session.SessionInformation;

import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * @author Rob Winch
 * @since 4.2
 */
public class SessionInformationExpiredEventTests {

	@Test
	public void constructorWhenSessionInformationNullThenThrowsException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new SessionInformationExpiredEvent(null,
				new MockHttpServletRequest(), new MockHttpServletResponse()));
	}

	@Test
	public void constructorWhenRequestNullThenThrowsException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new SessionInformationExpiredEvent(
				new SessionInformation("fake", "sessionId", new Date()), null, new MockHttpServletResponse()));
	}

	@Test
	public void constructorWhenResponseNullThenThrowsException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new SessionInformationExpiredEvent(
				new SessionInformation("fake", "sessionId", new Date()), new MockHttpServletRequest(), null));
	}

}
