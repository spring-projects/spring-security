/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.access.annotation;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.*;

import org.springframework.core.GenericTypeResolver;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.method.AbstractFallbackMethodSecurityMetadataSource;
import org.springframework.util.Assert;

/**
 * Sources method security metadata from Spring Security's {@link Secured} annotation.
 * <p>
 * Can also be used with custom security annotations by injecting an
 * {@link AnnotationMetadataExtractor}. The annotation type will then be obtained from the
 * generic parameter type supplied to this interface
 *
 * @author Ben Alex
 * @author Luke Taylor
 */
@SuppressWarnings({ "unchecked" })
public class SecuredAnnotationSecurityMetadataSource extends
		AbstractFallbackMethodSecurityMetadataSource {
	private AnnotationMetadataExtractor annotationExtractor;
	private Class<? extends Annotation> annotationType;

	public SecuredAnnotationSecurityMetadataSource() {
		this(new SecuredAnnotationMetadataExtractor());
	}

	public SecuredAnnotationSecurityMetadataSource(
			AnnotationMetadataExtractor annotationMetadataExtractor) {
		Assert.notNull(annotationMetadataExtractor);
		annotationExtractor = annotationMetadataExtractor;
		annotationType = (Class<? extends Annotation>) GenericTypeResolver
				.resolveTypeArgument(annotationExtractor.getClass(),
						AnnotationMetadataExtractor.class);
		Assert.notNull(annotationType, annotationExtractor.getClass().getName()
				+ " must supply a generic parameter for AnnotationMetadataExtractor");
	}

	protected Collection<ConfigAttribute> findAttributes(Class<?> clazz) {
		return processAnnotation(AnnotationUtils.findAnnotation(clazz, annotationType));
	}

	protected Collection<ConfigAttribute> findAttributes(Method method,
			Class<?> targetClass) {
		return processAnnotation(AnnotationUtils.findAnnotation(method, annotationType));
	}

	public Collection<ConfigAttribute> getAllConfigAttributes() {
		return null;
	}

	private Collection<ConfigAttribute> processAnnotation(Annotation a) {
		if (a == null) {
			return null;
		}

		return annotationExtractor.extractAttributes(a);
	}
}

class SecuredAnnotationMetadataExtractor implements AnnotationMetadataExtractor<Secured> {

	public Collection<ConfigAttribute> extractAttributes(Secured secured) {
		String[] attributeTokens = secured.value();
		List<ConfigAttribute> attributes = new ArrayList<ConfigAttribute>(
				attributeTokens.length);

		for (String token : attributeTokens) {
			attributes.add(new SecurityConfig(token));
		}

		return attributes;
	}
}
