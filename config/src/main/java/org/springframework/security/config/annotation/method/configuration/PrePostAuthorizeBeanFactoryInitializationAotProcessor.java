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

package org.springframework.security.config.annotation.method.configuration;

import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.aot.generate.GenerationContext;
import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.TypeReference;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.aot.BeanFactoryInitializationAotContribution;
import org.springframework.beans.factory.aot.BeanFactoryInitializationAotProcessor;
import org.springframework.beans.factory.aot.BeanFactoryInitializationCode;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.RegisteredBean;
import org.springframework.core.annotation.AnnotationConfigurationException;
import org.springframework.core.annotation.MergedAnnotation;
import org.springframework.core.annotation.MergedAnnotations;
import org.springframework.core.annotation.RepeatableContainers;
import org.springframework.core.log.LogMessage;
import org.springframework.expression.spel.SpelNode;
import org.springframework.expression.spel.ast.BeanReference;
import org.springframework.expression.spel.standard.SpelExpression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.util.ReflectionUtils;

/**
 * AOT BeanFactoryInitializationAotProcessor that detects the presence of
 * {@link PreAuthorize} and {@link PostAuthorize} on annotated elements of all registered
 * beans and register runtime hints for the beans used within the security expressions.
 *
 * @author Marcus da Coregio
 * @since 6.3
 */
class PrePostAuthorizeBeanFactoryInitializationAotProcessor implements BeanFactoryInitializationAotProcessor {

	@Override
	public BeanFactoryInitializationAotContribution processAheadOfTime(ConfigurableListableBeanFactory beanFactory) {
		Class<?>[] beanTypes = Arrays.stream(beanFactory.getBeanDefinitionNames())
			.map((beanName) -> RegisteredBean.of(beanFactory, beanName).getBeanClass())
			.toArray(Class<?>[]::new);
		return new PrePostAuthorizeContribution(beanTypes, beanFactory);
	}

	private static class PrePostAuthorizeContribution implements BeanFactoryInitializationAotContribution {

		private final Log logger = LogFactory.getLog(getClass());

		private final Class<?>[] types;

		private final ConfigurableListableBeanFactory beanFactory;

		private final SpelExpressionParser expressionParser = new SpelExpressionParser();

		PrePostAuthorizeContribution(Class<?>[] types, ConfigurableListableBeanFactory beanFactory) {
			this.types = types;
			this.beanFactory = beanFactory;
		}

		@Override
		public void applyTo(GenerationContext generationContext,
				BeanFactoryInitializationCode beanFactoryInitializationCode) {
			List<PreAuthorize> preAuthorizes = new ArrayList<>();
			List<PostAuthorize> postAuthorizes = new ArrayList<>();
			for (Class<?> type : this.types) {
				preAuthorizes.addAll(collectAnnotations(type, PreAuthorize.class));
				postAuthorizes.addAll(collectAnnotations(type, PostAuthorize.class));
			}
			Set<String> expressions = Stream
				.concat(preAuthorizes.stream().map(PreAuthorize::value),
						postAuthorizes.stream().map(PostAuthorize::value))
				.collect(Collectors.toSet());
			Set<String> beanNames = new HashSet<>();
			for (String expr : expressions) {
				beanNames.addAll(extractBeanNames(expr));
			}
			registerHints(beanNames, generationContext.getRuntimeHints());
		}

		private void registerHints(Set<String> beanNames, RuntimeHints runtimeHints) {
			for (String beanName : beanNames) {
				try {
					BeanDefinition definition = this.beanFactory.getBeanDefinition(beanName);
					runtimeHints.reflection()
						.registerType(TypeReference.of(definition.getBeanClassName()),
								MemberCategory.INVOKE_DECLARED_METHODS);
				}
				catch (NoSuchBeanDefinitionException ex) {
					this.logger.debug(LogMessage.format(
							"""
									Could not register runtime hints for bean with name [%s] because it is not available, please provide
									the needed hints manually""",
							beanName));
				}
			}
		}

		private <A extends Annotation> List<A> collectAnnotations(Class<?> type, Class<A> annotationType) {
			List<A> annotations = new ArrayList<>();
			A classAnnotation = findDistinctAnnotation(type, annotationType, MergedAnnotation::synthesize);
			if (classAnnotation != null) {
				annotations.add(classAnnotation);
			}
			for (Method method : type.getDeclaredMethods()) {
				A methodAnnotation = findDistinctAnnotation(method, annotationType, MergedAnnotation::synthesize);
				if (methodAnnotation != null) {
					annotations.add(methodAnnotation);
				}
			}
			return annotations;
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
				beanNames.add(resolveBeanName(br));
			}
			int childCount = node.getChildCount();
			if (childCount == 0) {
				return;
			}
			for (int i = 0; i < childCount; i++) {
				resolveBeanNames(beanNames, node.getChild(i));
			}
		}

		private String resolveBeanName(BeanReference br) {
			try {
				Field field = ReflectionUtils.findField(BeanReference.class, "beanName");
				field.setAccessible(true);
				return (String) field.get(br);
			}
			catch (IllegalAccessException ex) {
				throw new IllegalStateException("Could not resolve beanName for BeanReference [%s]".formatted(br), ex);
			}
		}

		private static <A extends Annotation> A findDistinctAnnotation(AnnotatedElement annotatedElement,
				Class<A> annotationType, Function<MergedAnnotation<A>, A> map) {
			MergedAnnotations mergedAnnotations = MergedAnnotations.from(annotatedElement,
					MergedAnnotations.SearchStrategy.TYPE_HIERARCHY, RepeatableContainers.none());
			List<A> annotations = mergedAnnotations.stream(annotationType)
				.map(MergedAnnotation::withNonMergedAttributes)
				.map(map)
				.distinct()
				.toList();

			return switch (annotations.size()) {
				case 0 -> null;
				case 1 -> annotations.get(0);
				default -> throw new AnnotationConfigurationException("""
						Please ensure there is one unique annotation of type @%s attributed to %s. \
						Found %d competing annotations: %s""".formatted(annotationType.getName(), annotatedElement,
						annotations.size(), annotations));
			};
		}

	}

}
