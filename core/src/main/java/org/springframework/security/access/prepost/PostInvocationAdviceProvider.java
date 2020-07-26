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
package org.springframework.security.access.prepost;

import java.util.Collection;

import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.AfterInvocationProvider;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;

/**
 * <tt>AfterInvocationProvider</tt> which delegates to a
 * {@link PostInvocationAuthorizationAdvice} instance passing it the
 * <tt>PostInvocationAttribute</tt> created from @PostAuthorize and @PostFilter
 * annotations.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class PostInvocationAdviceProvider implements AfterInvocationProvider {

	protected final Log logger = LogFactory.getLog(getClass());

	private final PostInvocationAuthorizationAdvice postAdvice;

	public PostInvocationAdviceProvider(PostInvocationAuthorizationAdvice postAdvice) {
		this.postAdvice = postAdvice;
	}

	@Override
	public Object decide(Authentication authentication, Object object, Collection<ConfigAttribute> config,
			Object returnedObject) throws AccessDeniedException {

		PostInvocationAttribute pia = findPostInvocationAttribute(config);

		if (pia == null) {
			return returnedObject;
		}

		return this.postAdvice.after(authentication, (MethodInvocation) object, pia, returnedObject);
	}

	private PostInvocationAttribute findPostInvocationAttribute(Collection<ConfigAttribute> config) {
		for (ConfigAttribute attribute : config) {
			if (attribute instanceof PostInvocationAttribute) {
				return (PostInvocationAttribute) attribute;
			}
		}

		return null;
	}

	@Override
	public boolean supports(ConfigAttribute attribute) {
		return attribute instanceof PostInvocationAttribute;
	}

	@Override
	public boolean supports(Class<?> clazz) {
		return clazz.isAssignableFrom(MethodInvocation.class);
	}

}
