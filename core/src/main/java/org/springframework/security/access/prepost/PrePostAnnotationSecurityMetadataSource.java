/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.access.prepost;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.core.log.LogMessage;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.method.AbstractMethodSecurityMetadataSource;
import org.springframework.util.ClassUtils;

/**
 * <tt>MethodSecurityMetadataSource</tt> which extracts metadata from the @PreFilter
 * and @PreAuthorize annotations placed on a method. This class is merely responsible for
 * locating the relevant annotations (if any). It delegates the actual
 * <tt>ConfigAttribute</tt> creation to its {@link PrePostInvocationAttributeFactory},
 * thus decoupling itself from the mechanism which will enforce the annotations'
 * behaviour.
 * <p>
 * Annotations may be specified on classes or methods, and method-specific annotations
 * will take precedence. If you use any annotation and do not specify a pre-authorization
 * condition, then the method will be allowed as if a @PreAuthorize("permitAll") were
 * present.
 * <p>
 * Since we are handling multiple annotations here, it's possible that we may have to
 * combine annotations defined in multiple locations for a single method - they may be
 * defined on the method itself, or at interface or class level.
 *
 * @author Luke Taylor
 * @since 3.0
 * @see PreInvocationAuthorizationAdviceVoter
 * @deprecated Use
 * {@link org.springframework.security.authorization.method.PreAuthorizeAuthorizationManager}
 * and
 * {@link org.springframework.security.authorization.method.PostAuthorizeAuthorizationManager}
 * instead
 */
@Deprecated
public class PrePostAnnotationSecurityMetadataSource extends AbstractMethodSecurityMetadataSource {

	private final PrePostInvocationAttributeFactory attributeFactory;

	public PrePostAnnotationSecurityMetadataSource(PrePostInvocationAttributeFactory attributeFactory) {
		this.attributeFactory = attributeFactory;
	}

	@Override
	public Collection<ConfigAttribute> getAttributes(Method method, Class<?> targetClass) {
		if (method.getDeclaringClass() == Object.class) {
			return Collections.emptyList();
		}
		PreFilter preFilter = findAnnotation(method, targetClass, PreFilter.class);
		PreAuthorize preAuthorize = findAnnotation(method, targetClass, PreAuthorize.class);
		PostFilter postFilter = findAnnotation(method, targetClass, PostFilter.class);
		// TODO: Can we check for void methods and throw an exception here?
		PostAuthorize postAuthorize = findAnnotation(method, targetClass, PostAuthorize.class);
		if (preFilter == null && preAuthorize == null && postFilter == null && postAuthorize == null) {
			// There is no meta-data so return
			return Collections.emptyList();
		}
		String preFilterAttribute = (preFilter != null) ? preFilter.value() : null;
		String filterObject = (preFilter != null) ? preFilter.filterTarget() : null;
		String preAuthorizeAttribute = (preAuthorize != null) ? preAuthorize.value() : null;
		String postFilterAttribute = (postFilter != null) ? postFilter.value() : null;
		String postAuthorizeAttribute = (postAuthorize != null) ? postAuthorize.value() : null;
		ArrayList<ConfigAttribute> attrs = new ArrayList<>(2);
		PreInvocationAttribute pre = this.attributeFactory.createPreInvocationAttribute(preFilterAttribute,
				filterObject, preAuthorizeAttribute);
		if (pre != null) {
			attrs.add(pre);
		}
		PostInvocationAttribute post = this.attributeFactory.createPostInvocationAttribute(postFilterAttribute,
				postAuthorizeAttribute);
		if (post != null) {
			attrs.add(post);
		}
		attrs.trimToSize();
		return attrs;
	}

	@Override
	public Collection<ConfigAttribute> getAllConfigAttributes() {
		return null;
	}

	/**
	 * See
	 * {@link org.springframework.security.access.method.AbstractFallbackMethodSecurityMetadataSource#getAttributes(Method, Class)}
	 * for the logic of this method. The ordering here is slightly different in that we
	 * consider method-specific annotations on an interface before class-level ones.
	 */
	private <A extends Annotation> A findAnnotation(Method method, Class<?> targetClass, Class<A> annotationClass) {
		// The method may be on an interface, but we need attributes from the target
		// class.
		// If the target class is null, the method will be unchanged.
		Method specificMethod = ClassUtils.getMostSpecificMethod(method, targetClass);
		A annotation = AnnotationUtils.findAnnotation(specificMethod, annotationClass);
		if (annotation != null) {
			this.logger.debug(LogMessage.format("%s found on specific method: %s", annotation, specificMethod));
			return annotation;
		}
		// Check the original (e.g. interface) method
		if (specificMethod != method) {
			annotation = AnnotationUtils.findAnnotation(method, annotationClass);
			if (annotation != null) {
				this.logger.debug(LogMessage.format("%s found on: %s", annotation, method));
				return annotation;
			}
		}
		// Check the class-level (note declaringClass, not targetClass, which may not
		// actually implement the method)
		annotation = AnnotationUtils.findAnnotation(specificMethod.getDeclaringClass(), annotationClass);
		if (annotation != null) {
			this.logger.debug(
					LogMessage.format("%s found on: %s", annotation, specificMethod.getDeclaringClass().getName()));
			return annotation;
		}
		return null;
	}

}
