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

package org.springframework.security.access.method;

import java.lang.reflect.Method;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.core.log.LogMessage;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;

/**
 * Automatically tries a series of method definition sources, relying on the first source
 * of metadata that provides a non-null/non-empty response. Provides automatic caching of
 * the retrieved metadata.
 *
 * @author Ben Alex
 * @author Luke Taylor
 */
public final class DelegatingMethodSecurityMetadataSource extends AbstractMethodSecurityMetadataSource {

	private static final List<ConfigAttribute> NULL_CONFIG_ATTRIBUTE = Collections.emptyList();

	private final List<MethodSecurityMetadataSource> methodSecurityMetadataSources;

	private final Map<DefaultCacheKey, Collection<ConfigAttribute>> attributeCache = new HashMap<>();

	public DelegatingMethodSecurityMetadataSource(List<MethodSecurityMetadataSource> methodSecurityMetadataSources) {
		Assert.notNull(methodSecurityMetadataSources, "MethodSecurityMetadataSources cannot be null");
		this.methodSecurityMetadataSources = methodSecurityMetadataSources;
	}

	@Override
	public Collection<ConfigAttribute> getAttributes(Method method, Class<?> targetClass) {
		DefaultCacheKey cacheKey = new DefaultCacheKey(method, targetClass);
		synchronized (this.attributeCache) {
			Collection<ConfigAttribute> cached = this.attributeCache.get(cacheKey);
			// Check for canonical value indicating there is no config attribute,
			if (cached != null) {
				return cached;
			}
			// No cached value, so query the sources to find a result
			Collection<ConfigAttribute> attributes = null;
			for (MethodSecurityMetadataSource s : this.methodSecurityMetadataSources) {
				attributes = s.getAttributes(method, targetClass);
				if (attributes != null && !attributes.isEmpty()) {
					break;
				}
			}
			// Put it in the cache.
			if (attributes == null || attributes.isEmpty()) {
				this.attributeCache.put(cacheKey, NULL_CONFIG_ATTRIBUTE);
				return NULL_CONFIG_ATTRIBUTE;
			}
			this.logger.debug(LogMessage.format("Caching method [%s] with attributes %s", cacheKey, attributes));
			this.attributeCache.put(cacheKey, attributes);
			return attributes;
		}
	}

	@Override
	public Collection<ConfigAttribute> getAllConfigAttributes() {
		Set<ConfigAttribute> set = new HashSet<>();
		for (MethodSecurityMetadataSource s : this.methodSecurityMetadataSources) {
			Collection<ConfigAttribute> attrs = s.getAllConfigAttributes();
			if (attrs != null) {
				set.addAll(attrs);
			}
		}
		return set;
	}

	public List<MethodSecurityMetadataSource> getMethodSecurityMetadataSources() {
		return this.methodSecurityMetadataSources;
	}

	private static class DefaultCacheKey {

		private final Method method;

		private final Class<?> targetClass;

		DefaultCacheKey(Method method, Class<?> targetClass) {
			this.method = method;
			this.targetClass = targetClass;
		}

		@Override
		public boolean equals(Object other) {
			DefaultCacheKey otherKey = (DefaultCacheKey) other;
			return (this.method.equals(otherKey.method)
					&& ObjectUtils.nullSafeEquals(this.targetClass, otherKey.targetClass));
		}

		@Override
		public int hashCode() {
			return this.method.hashCode() * 21 + ((this.targetClass != null) ? this.targetClass.hashCode() : 0);
		}

		@Override
		public String toString() {
			String targetClassName = (this.targetClass != null) ? this.targetClass.getName() : "-";
			return "CacheKey[" + targetClassName + "; " + this.method + "]";
		}

	}

}
