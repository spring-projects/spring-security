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

package org.springframework.security.messaging.util.matcher;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.context.support.GenericApplicationContext;
import org.springframework.web.util.pattern.PathPatternParser;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class PathPatternMessageMatcherBuilderFactoryBeanTests {

	GenericApplicationContext context;

	@BeforeEach
	void setUp() {
		this.context = new GenericApplicationContext();
	}

	@Test
	void getObjectWhenDefaultsThenBuilder() throws Exception {
		factoryBean().getObject();
	}

	@Test
	void getObjectWithCustomParserThenUses() throws Exception {
		PathPatternParser parser = mock(PathPatternParser.class);
		PathPatternMessageMatcher.Builder builder = factoryBean(parser).getObject();

		builder.matcher("/path/**");
		verify(parser).parse("/path/**");
	}

	PathPatternMessageMatcherBuilderFactoryBean factoryBean() {
		PathPatternMessageMatcherBuilderFactoryBean factoryBean = new PathPatternMessageMatcherBuilderFactoryBean();
		return factoryBean;
	}

	PathPatternMessageMatcherBuilderFactoryBean factoryBean(PathPatternParser parser) {
		PathPatternMessageMatcherBuilderFactoryBean factoryBean = new PathPatternMessageMatcherBuilderFactoryBean(
				parser);
		return factoryBean;
	}

}
