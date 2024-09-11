/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.aot.hint;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.TypeReference;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.expression.spel.SpelNode;
import org.springframework.expression.spel.ast.BeanReference;
import org.springframework.expression.spel.standard.SpelExpression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.method.AuthorizeReturnObject;
import org.springframework.security.core.annotation.SecurityAnnotationScanner;
import org.springframework.security.core.annotation.SecurityAnnotationScanners;
import org.springframework.util.Assert;

/**
 * A {@link SecurityHintsRegistrar} that scans all provided classes for methods that use
 * {@link PreAuthorize} or {@link PostAuthorize} and registers hints for the beans used
 * within the security expressions.
 *
 * <p>
 * It will also scan return types of methods annotated with {@link AuthorizeReturnObject}.
 *
 * <p>
 * This may be used by an application to register specific Security-adjacent classes that
 * were otherwise missed by Spring Security's reachability scans.
 *
 * <p>
 * Remember to register this as an infrastructural bean like so:
 *
 * <pre>
 *	&#064;Bean
 *	&#064;Role(BeanDefinition.ROLE_INFRASTRUCTURE)
 *	static SecurityHintsRegistrar registerThese() {
 *		return new PrePostAuthorizeExpressionBeanHintsRegistrar(MyClass.class);
 *	}
 * </pre>
 *
 * @author Marcus da Coregio
 * @since 6.4
 * @see SecurityHintsAotProcessor
 */
public final class PrePostAuthorizeExpressionBeanHintsRegistrar implements SecurityHintsRegistrar {

	private final SecurityAnnotationScanner<PreAuthorize> preAuthorizeScanner = SecurityAnnotationScanners
		.requireUnique(PreAuthorize.class);

	private final SecurityAnnotationScanner<PostAuthorize> postAuthorizeScanner = SecurityAnnotationScanners
		.requireUnique(PostAuthorize.class);

	private final SecurityAnnotationScanner<AuthorizeReturnObject> authorizeReturnObjectScanner = SecurityAnnotationScanners
		.requireUnique(AuthorizeReturnObject.class);

	private final SpelExpressionParser expressionParser = new SpelExpressionParser();

	private final Set<Class<?>> visitedClasses = new HashSet<>();

	private final List<Class<?>> toVisit;

	public PrePostAuthorizeExpressionBeanHintsRegistrar(Class<?>... toVisit) {
		this(Arrays.asList(toVisit));
	}

	public PrePostAuthorizeExpressionBeanHintsRegistrar(List<Class<?>> toVisit) {
		Assert.notEmpty(toVisit, "toVisit cannot be empty");
		Assert.noNullElements(toVisit, "toVisit cannot contain null elements");
		this.toVisit = toVisit;
	}

	@Override
	public void registerHints(RuntimeHints hints, ConfigurableListableBeanFactory beanFactory) {
		Set<String> expressions = new HashSet<>();
		for (Class<?> bean : this.toVisit) {
			expressions.addAll(extractSecurityExpressions(bean));
		}
		Set<String> beanNamesToRegister = new HashSet<>();
		for (String expression : expressions) {
			beanNamesToRegister.addAll(extractBeanNames(expression));
		}
		for (String toRegister : beanNamesToRegister) {
			Class<?> type = beanFactory.getType(toRegister, false);
			if (type == null) {
				continue;
			}
			hints.reflection().registerType(TypeReference.of(type), MemberCategory.INVOKE_DECLARED_METHODS);
		}
	}

	private Set<String> extractSecurityExpressions(Class<?> clazz) {
		if (this.visitedClasses.contains(clazz)) {
			return Collections.emptySet();
		}
		this.visitedClasses.add(clazz);
		Set<String> expressions = new HashSet<>();
		for (Method method : clazz.getDeclaredMethods()) {
			PreAuthorize preAuthorize = this.preAuthorizeScanner.scan(method, clazz);
			PostAuthorize postAuthorize = this.postAuthorizeScanner.scan(method, clazz);
			if (preAuthorize != null) {
				expressions.add(preAuthorize.value());
			}
			if (postAuthorize != null) {
				expressions.add(postAuthorize.value());
			}
			AuthorizeReturnObject authorizeReturnObject = this.authorizeReturnObjectScanner.scan(method, clazz);
			if (authorizeReturnObject != null) {
				expressions.addAll(extractSecurityExpressions(method.getReturnType()));
			}
		}
		return expressions;
	}

	private Set<String> extractBeanNames(String rawExpression) {
		SpelExpression expression = this.expressionParser.parseRaw(rawExpression);
		SpelNode node = expression.getAST();
		Set<String> beanNames = new HashSet<>();
		resolveBeanNames(beanNames, node);
		return beanNames;
	}

	private void resolveBeanNames(Set<String> beanNames, SpelNode node) {
		if (node instanceof BeanReference br) {
			beanNames.add(br.getName());
		}
		int childCount = node.getChildCount();
		if (childCount == 0) {
			return;
		}
		for (int i = 0; i < childCount; i++) {
			resolveBeanNames(beanNames, node.getChild(i));
		}
	}

}
