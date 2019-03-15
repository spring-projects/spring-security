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
package org.springframework.security.web.header.writers.frameoptions;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.header.writers.frameoptions.StaticAllowFromStrategy;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for the StaticAllowFromStrategy.
 *
 * @author Marten Deinum
 * @since 3.2
 */
public class StaticAllowFromStrategyTests {

	@Test
	public void shouldReturnUri() {
		String uri = "http://www.test.com";
		StaticAllowFromStrategy strategy = new StaticAllowFromStrategy(URI.create(uri));
		assertThat(strategy.getAllowFromValue(new MockHttpServletRequest())).isEqualTo(uri);
	}
}
