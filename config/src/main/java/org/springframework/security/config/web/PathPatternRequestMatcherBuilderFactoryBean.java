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

import reactor.util.annotation.NonNull;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.BeanNameAware;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
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
public final class PathPatternRequestMatcherBuilderFactoryBean implements
		FactoryBean<PathPatternRequestMatcher.Builder>, ApplicationContextAware, BeanNameAware, BeanFactoryAware {

	static final String MVC_PATTERN_PARSER_BEAN_NAME = "mvcPatternParser";

	private final PathPatternParser parser;

	private String basePath;

	private ApplicationContext context;

	private String beanName;

	private ConfigurableListableBeanFactory beanFactory;

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
		if (!this.context.containsBean(MVC_PATTERN_PARSER_BEAN_NAME)) {
			PathPatternParser parser = (this.parser != null) ? this.parser : PathPatternParser.defaultInstance;
			return withPathPatternParser(parser);
		}
		PathPatternParser mvc = this.context.getBean(MVC_PATTERN_PARSER_BEAN_NAME, PathPatternParser.class);
		PathPatternParser parser = (this.parser != null) ? this.parser : mvc;
		if (mvc.equals(parser)) {
			return withPathPatternParser(parser);
		}
		throw new IllegalArgumentException("Spring Security and Spring MVC must use the same path pattern parser. "
				+ "To have Spring Security use Spring MVC's [" + describe(mvc, MVC_PATTERN_PARSER_BEAN_NAME)
				+ "] simply publish this bean [" + describe(this, this.beanName) + "] using its default constructor");
	}

	private PathPatternRequestMatcher.Builder withPathPatternParser(PathPatternParser parser) {
		if (this.basePath == null) {
			return PathPatternRequestMatcher.withPathPatternParser(parser);
		}
		else {
			return PathPatternRequestMatcher.withPathPatternParser(parser).basePath(this.basePath);
		}
	}

	@Override
	public Class<?> getObjectType() {
		return PathPatternRequestMatcher.Builder.class;
	}

	/**
	 * Use this as the base path for patterns built by the resulting
	 * {@link PathPatternRequestMatcher.Builder} instance
	 * @param basePath the base path to use
	 * @since 7.0
	 * @see PathPatternRequestMatcher.Builder#basePath(String)
	 */
	public void setBasePath(String basePath) {
		this.basePath = basePath;
	}

	@Override
	public void setApplicationContext(ApplicationContext context) throws BeansException {
		this.context = context;
	}

	@Override
	public void setBeanName(@NonNull String name) {
		this.beanName = name;
	}

	@Override
	public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
		if (beanFactory instanceof ConfigurableListableBeanFactory listable) {
			this.beanFactory = listable;
		}
	}

	private String describe(Object bean, String name) {
		String text = bean.getClass().getSimpleName();
		if (name == null) {
			return text;
		}
		text += "defined as '" + name + "'";
		if (this.beanFactory == null) {
			return text;
		}
		BeanDefinition bd = this.beanFactory.getBeanDefinition(name);
		String description = bd.getResourceDescription();
		if (description == null) {
			return text;
		}
		text += " in [" + description + "]";
		return text;
	}

}
