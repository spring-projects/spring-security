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

package org.springframework.security.config.web;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.context.support.GenericApplicationContext;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.web.util.pattern.PathPatternParser;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class PathPatternRequestMatcherBuilderFactoryBeanTests {

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
	void getObjectWhenMvcPatternParserThenUses() throws Exception {
		PathPatternParser mvc = registerMvcPatternParser();
		PathPatternRequestMatcher.Builder builder = factoryBean().getObject();
		builder.matcher("/path/**");
		verify(mvc).parse("/path/**");
	}

	@Test
	void getObjectWhenPathPatternParserThenUses() throws Exception {
		PathPatternParser parser = mock(PathPatternParser.class);
		PathPatternRequestMatcher.Builder builder = factoryBean(parser).getObject();
		builder.matcher("/path/**");
		verify(parser).parse("/path/**");
	}

	@Test
	void getObjectWhenMvcAndPathPatternParserConflictThenIllegalArgument() {
		registerMvcPatternParser();
		PathPatternParser parser = mock(PathPatternParser.class);
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> factoryBean(parser).getObject());
	}

	@Test
	void getObjectWhenMvcAndPathPatternParserAgreeThenUses() throws Exception {
		PathPatternParser mvc = registerMvcPatternParser();
		PathPatternRequestMatcher.Builder builder = factoryBean(mvc).getObject();
		builder.matcher("/path/**");
		verify(mvc).parse("/path/**");
	}

	PathPatternRequestMatcherBuilderFactoryBean factoryBean() {
		PathPatternRequestMatcherBuilderFactoryBean factoryBean = new PathPatternRequestMatcherBuilderFactoryBean();
		factoryBean.setApplicationContext(this.context);
		return factoryBean;
	}

	PathPatternRequestMatcherBuilderFactoryBean factoryBean(PathPatternParser parser) {
		PathPatternRequestMatcherBuilderFactoryBean factoryBean = new PathPatternRequestMatcherBuilderFactoryBean(
				parser);
		factoryBean.setApplicationContext(this.context);
		return factoryBean;
	}

	PathPatternParser registerMvcPatternParser() {
		PathPatternParser mvc = mock(PathPatternParser.class);
		this.context.registerBean(PathPatternRequestMatcherBuilderFactoryBean.PATTERN_PARSER_BEAN_NAME,
				PathPatternParser.class, () -> mvc);
		this.context.refresh();
		return mvc;
	}

}
