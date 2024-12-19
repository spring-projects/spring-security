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

package org.springframework.security.core.annotation;

import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Executable;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.core.MethodClassKey;
import org.springframework.core.annotation.AnnotationConfigurationException;
import org.springframework.core.annotation.MergedAnnotation;
import org.springframework.core.annotation.MergedAnnotations;
import org.springframework.core.annotation.RepeatableContainers;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;

/**
 * Searches for and synthesizes annotations found on types, methods, or method parameters
 * into an annotation of type {@code <A>}, ensuring that there is a unique match.
 *
 * <p>
 * Note that in all cases, Spring Security does not allow for repeatable annotations. As
 * such, this class errors if a repeat is discovered.
 *
 * <p>
 * For example, if a class extends two interfaces, and each interface is annotated with
 * `@PreAuthorize("hasRole('ADMIN')")` and `@PreAuthorize("hasRole('USER')")`
 * respectively, it's not clear which of these should apply, and so this class will throw
 * an exception.
 *
 * <p>
 * If the given annotation can be applied to types or methods, this class will traverse
 * the type hierarchy, starting from the target class and method; in case of a method
 * parameter, it will only consider annotations on the parameter. In all cases, it will
 * consider meta-annotations in its traversal.
 *
 * <p>
 * When traversing the type hierarchy, this class will first look for annotations on the
 * given method, then on any methods that method overrides. If no annotations are found,
 * it will then search for annotations on the given class, then on any classes that class
 * extends and on any interfaces that class implements.
 *
 * <p>
 * It supports meta-annotations, like the following:
 *
 * <pre>
 *	&#64;PreAuthorize("hasRole('ROLE_ADMIN')")
 *	public @annotation HasRole {
 *	}
 * </pre>
 *
 * <p>
 * In that case, you can use an {@link UniqueSecurityAnnotationScanner} of type
 * {@link org.springframework.security.access.prepost.PreAuthorize} to synthesize any
 * {@code @HasRole} annotation found on a given method or class into its
 * {@link org.springframework.security.access.prepost.PreAuthorize} meta-annotation.
 *
 * <p>
 * Since the process of synthesis is expensive, it's recommended to cache the synthesized
 * result to prevent multiple computations.
 *
 * @param <A> the annotation to search for and synthesize
 * @author Josh Cummings
 * @author DingHao
 * @since 6.4
 */
final class UniqueSecurityAnnotationScanner<A extends Annotation> extends AbstractSecurityAnnotationScanner<A> {

	private final List<Class<A>> types;

	private final Map<Parameter, MergedAnnotation<A>> uniqueParameterAnnotationCache = new ConcurrentHashMap<>();

	private final Map<MethodClassKey, MergedAnnotation<A>> uniqueMethodAnnotationCache = new ConcurrentHashMap<>();

	UniqueSecurityAnnotationScanner(Class<A> type) {
		Assert.notNull(type, "type cannot be null");
		this.types = List.of(type);
	}

	UniqueSecurityAnnotationScanner(List<Class<A>> types) {
		Assert.notNull(types, "types cannot be null");
		this.types = types;
	}

	@Override
	MergedAnnotation<A> merge(AnnotatedElement element, Class<?> targetClass) {
		if (element instanceof Parameter parameter) {
			return this.uniqueParameterAnnotationCache.computeIfAbsent(parameter, (p) -> {
				List<MergedAnnotation<A>> annotations = findParameterAnnotations(p);
				return requireUnique(p, annotations);
			});
		}
		if (element instanceof Method method) {
			return this.uniqueMethodAnnotationCache.computeIfAbsent(new MethodClassKey(method, targetClass), (k) -> {
				List<MergedAnnotation<A>> annotations = findMethodAnnotations(method, targetClass);
				return requireUnique(method, annotations);
			});
		}
		throw new AnnotationConfigurationException("Unsupported element of type " + element.getClass());
	}

	private MergedAnnotation<A> requireUnique(AnnotatedElement element, List<MergedAnnotation<A>> annotations) {
		return switch (annotations.size()) {
			case 0 -> null;
			case 1 -> annotations.get(0);
			default -> {
				List<Annotation> synthesized = new ArrayList<>();
				for (MergedAnnotation<A> annotation : annotations) {
					synthesized.add(annotation.synthesize());
				}
				throw new AnnotationConfigurationException("""
						Please ensure there is one unique annotation of type %s attributed to %s. \
						Found %d competing annotations: %s""".formatted(this.types, element, annotations.size(),
						synthesized));
			}
		};
	}

	private List<MergedAnnotation<A>> findParameterAnnotations(Parameter current) {
		List<MergedAnnotation<A>> directAnnotations = findDirectAnnotations(current);
		if (!directAnnotations.isEmpty()) {
			return directAnnotations;
		}
		Executable executable = current.getDeclaringExecutable();
		if (executable instanceof Method method) {
			Class<?> clazz = method.getDeclaringClass();
			Set<Class<?>> visited = new HashSet<>();
			while (clazz != null && clazz != Object.class) {
				directAnnotations = findClosestParameterAnnotations(method, clazz, current, visited);
				if (!directAnnotations.isEmpty()) {
					return directAnnotations;
				}
				clazz = clazz.getSuperclass();
			}
		}
		return Collections.emptyList();
	}

	private List<MergedAnnotation<A>> findClosestParameterAnnotations(Method method, Class<?> clazz, Parameter current,
			Set<Class<?>> visited) {
		if (!visited.add(clazz)) {
			return Collections.emptyList();
		}
		List<MergedAnnotation<A>> annotations = new ArrayList<>(findDirectParameterAnnotations(method, clazz, current));
		for (Class<?> ifc : clazz.getInterfaces()) {
			annotations.addAll(findClosestParameterAnnotations(method, ifc, current, visited));
		}
		return annotations;
	}

	private List<MergedAnnotation<A>> findDirectParameterAnnotations(Method method, Class<?> clazz, Parameter current) {
		try {
			Method methodToUse = clazz.getDeclaredMethod(method.getName(), method.getParameterTypes());
			for (Parameter parameter : methodToUse.getParameters()) {
				if (parameter.getName().equals(current.getName())) {
					List<MergedAnnotation<A>> directAnnotations = findDirectAnnotations(parameter);
					if (!directAnnotations.isEmpty()) {
						return directAnnotations;
					}
				}
			}
		}
		catch (NoSuchMethodException ex) {
			// move on
		}
		return Collections.emptyList();
	}

	private List<MergedAnnotation<A>> findMethodAnnotations(Method method, Class<?> targetClass) {
		// The method may be on an interface, but we need attributes from the target
		// class.
		// If the target class is null, the method will be unchanged.
		Method specificMethod = ClassUtils.getMostSpecificMethod(method, targetClass);
		List<MergedAnnotation<A>> annotations = findClosestMethodAnnotations(specificMethod,
				specificMethod.getDeclaringClass(), new HashSet<>());
		if (!annotations.isEmpty()) {
			return annotations;
		}
		// Check the original (e.g. interface) method
		if (specificMethod != method) {
			annotations = findClosestMethodAnnotations(method, method.getDeclaringClass(), new HashSet<>());
			if (!annotations.isEmpty()) {
				return annotations;
			}
		}
		// Check the class-level (note declaringClass, not targetClass, which may not
		// actually implement the method)
		annotations = findClosestClassAnnotations(specificMethod.getDeclaringClass(), new HashSet<>());
		if (!annotations.isEmpty()) {
			return annotations;
		}
		return Collections.emptyList();
	}

	private List<MergedAnnotation<A>> findClosestMethodAnnotations(Method method, Class<?> targetClass,
			Set<Class<?>> classesToSkip) {
		if (targetClass == null || classesToSkip.contains(targetClass) || targetClass == Object.class) {
			return Collections.emptyList();
		}
		classesToSkip.add(targetClass);
		try {
			Method methodToUse = targetClass.getDeclaredMethod(method.getName(), method.getParameterTypes());
			List<MergedAnnotation<A>> annotations = findDirectAnnotations(methodToUse);
			if (!annotations.isEmpty()) {
				return annotations;
			}
		}
		catch (NoSuchMethodException ex) {
			// move on
		}
		List<MergedAnnotation<A>> annotations = new ArrayList<>();
		annotations.addAll(findClosestMethodAnnotations(method, targetClass.getSuperclass(), classesToSkip));
		for (Class<?> inter : targetClass.getInterfaces()) {
			annotations.addAll(findClosestMethodAnnotations(method, inter, classesToSkip));
		}
		return annotations;
	}

	private List<MergedAnnotation<A>> findClosestClassAnnotations(Class<?> targetClass, Set<Class<?>> classesToSkip) {
		if (targetClass == null || classesToSkip.contains(targetClass) || targetClass == Object.class) {
			return Collections.emptyList();
		}
		classesToSkip.add(targetClass);
		List<MergedAnnotation<A>> annotations = new ArrayList<>(findDirectAnnotations(targetClass));
		if (!annotations.isEmpty()) {
			return annotations;
		}
		annotations.addAll(findClosestClassAnnotations(targetClass.getSuperclass(), classesToSkip));
		for (Class<?> inter : targetClass.getInterfaces()) {
			annotations.addAll(findClosestClassAnnotations(inter, classesToSkip));
		}
		return annotations;
	}

	private List<MergedAnnotation<A>> findDirectAnnotations(AnnotatedElement element) {
		MergedAnnotations mergedAnnotations = MergedAnnotations.from(element, MergedAnnotations.SearchStrategy.DIRECT,
				RepeatableContainers.none());
		return mergedAnnotations.stream()
			.filter((annotation) -> this.types.contains(annotation.getType()))
			.map((annotation) -> (MergedAnnotation<A>) annotation)
			.toList();
	}

}
