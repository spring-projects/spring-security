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

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.web.util.pattern.PathPatternParser;

/**
 * Use this factory bean to configure the {@link PathPatternRequestMatcher.Builder} bean
 * used to create request matchers in {@link AuthorizeHttpRequestsConfigurer} and other
 * parts of the DSL.
 *
 * @author Josh Cummings
 * @since 6.5
 */
public final class PathPatternRequestMatcherBuilderFactoryBean
		implements FactoryBean<PathPatternRequestMatcher.Builder>, ApplicationContextAware {

	static final String PATTERN_PARSER_BEAN_NAME = "mvcPatternParser";

	private final PathPatternParser parser;

	private ApplicationContext context;

	/**
	 * Construct this factory bean using the default {@link PathPatternParser}
	 *
	 * <p>
	 * If you are using Spring MVC, it will use the Spring MVC instance.
	 */
	public PathPatternRequestMatcherBuilderFactoryBean() {
		this(null);
	}

	/**
	 * Construct this factory bean using this {@link PathPatternParser}.
	 *
	 * <p>
	 * If you are using Spring MVC, it is likely incorrect to call this constructor.
	 * Please call the default constructor instead.
	 * @param parser the {@link PathPatternParser} to use
	 */
	public PathPatternRequestMatcherBuilderFactoryBean(PathPatternParser parser) {
		this.parser = parser;
	}

	@Override
	public PathPatternRequestMatcher.Builder getObject() throws Exception {
		if (!this.context.containsBean(PATTERN_PARSER_BEAN_NAME)) {
			PathPatternParser parser = (this.parser != null) ? this.parser : PathPatternParser.defaultInstance;
			return PathPatternRequestMatcher.withPathPatternParser(parser);
		}
		PathPatternParser mvc = this.context.getBean(PATTERN_PARSER_BEAN_NAME, PathPatternParser.class);
		PathPatternParser parser = (this.parser != null) ? this.parser : mvc;
		if (mvc.equals(parser)) {
			return PathPatternRequestMatcher.withPathPatternParser(parser);
		}
		throw new IllegalArgumentException("Spring Security and Spring MVC must use the same path pattern parser. "
				+ "To have Spring Security use Spring MVC's simply publish this bean ["
				+ this.getClass().getSimpleName() + "] using its default constructor");
	}

	@Override
	public Class<?> getObjectType() {
		return PathPatternRequestMatcher.Builder.class;
	}

	@Override
	public void setApplicationContext(ApplicationContext context) throws BeansException {
		this.context = context;
	}

}
