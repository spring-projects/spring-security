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

package org.springframework.security.access.intercept;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jspecify.annotations.NullUnmarked;
import org.jspecify.annotations.Nullable;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.log.LogMessage;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.AfterInvocationProvider;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

/**
 * Provider-based implementation of {@link AfterInvocationManager}.
 * <p>
 * Handles configuration of a bean context defined list of {@link AfterInvocationProvider}
 * s.
 * <p>
 * Every <code>AfterInvocationProvider</code> will be polled when the
 * {@link #decide(Authentication, Object, Collection, Object)} method is called. The
 * <code>Object</code> returned from each provider will be presented to the successive
 * provider for processing. This means each provider <b>must</b> ensure they return the
 * <code>Object</code>, even if they are not interested in the "after invocation" decision
 * (perhaps as the secure object invocation did not include a configuration attribute a
 * given provider is configured to respond to).
 *
 * @author Ben Alex
 * @see org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor
 * @see org.springframework.security.authorization.method.AuthorizationManagerAfterMethodInterceptor
 * @deprecated Use delegation with {@link AuthorizationManager}
 */
@NullUnmarked
@Deprecated
public class AfterInvocationProviderManager implements AfterInvocationManager, InitializingBean {

	protected static final Log logger = LogFactory.getLog(AfterInvocationProviderManager.class);

	@SuppressWarnings("NullAway.Init")
	private @Nullable List<AfterInvocationProvider> providers;

	@Override
	public void afterPropertiesSet() {
		checkIfValidList(this.providers);
	}

	@Override
	public Object decide(Authentication authentication, Object object, Collection<ConfigAttribute> config,
			Object returnedObject) throws AccessDeniedException {
		Object result = returnedObject;
		for (AfterInvocationProvider provider : this.providers) {
			result = provider.decide(authentication, object, config, result);
		}
		return result;
	}

	public List<AfterInvocationProvider> getProviders() {
		return this.providers;
	}

	public void setProviders(List<?> newList) {
		checkIfValidList(newList);
		this.providers = new ArrayList<>(newList.size());
		for (Object currentObject : newList) {
			Assert.isInstanceOf(AfterInvocationProvider.class, currentObject, () -> "AfterInvocationProvider "
					+ currentObject.getClass().getName() + " must implement AfterInvocationProvider");
			this.providers.add((AfterInvocationProvider) currentObject);
		}
	}

	private void checkIfValidList(List<?> listToCheck) {
		Assert.isTrue(!CollectionUtils.isEmpty(listToCheck), "A list of AfterInvocationProviders is required");
	}

	@Override
	public boolean supports(ConfigAttribute attribute) {
		for (AfterInvocationProvider provider : this.providers) {
			logger.debug(LogMessage.format("Evaluating %s against %s", attribute, provider));
			if (provider.supports(attribute)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Iterates through all <code>AfterInvocationProvider</code>s and ensures each can
	 * support the presented class.
	 * <p>
	 * If one or more providers cannot support the presented class, <code>false</code> is
	 * returned.
	 * @param clazz the secure object class being queries
	 * @return if the <code>AfterInvocationProviderManager</code> can support the secure
	 * object class, which requires every one of its <code>AfterInvocationProvider</code>s
	 * to support the secure object class
	 */
	@Override
	public boolean supports(Class<?> clazz) {
		for (AfterInvocationProvider provider : this.providers) {
			if (!provider.supports(clazz)) {
				return false;
			}
		}
		return true;
	}

}
