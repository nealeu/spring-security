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

import org.springframework.security.access.ConfigAttribute;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;

import java.lang.reflect.Method;
import java.util.*;

/**
 * Looks up attributes in a delegate metadata source. Provides automatic caching of
 * the retrieved metadata.
 *
 * @author Ben Alex
 * @author Luke Taylor
 */
public final class CachingMethodSecurityMetadataSource extends
		AbstractMethodSecurityMetadataSource {
	private final static List<ConfigAttribute> NULL_CONFIG_ATTRIBUTE = Collections
			.emptyList();

	private final MethodSecurityMetadataSource methodSecurityMetadataSource;
	private final Map<DefaultCacheKey, Collection<ConfigAttribute>> attributeCache = new HashMap<>();

	// ~ Constructor
	// ====================================================================================================

	public CachingMethodSecurityMetadataSource(
			MethodSecurityMetadataSource methodSecurityMetadataSource) {
		Assert.notNull(methodSecurityMetadataSource,
				"MethodSecurityMetadataSources cannot be null");
		this.methodSecurityMetadataSource = methodSecurityMetadataSource;
	}

	// ~ Methods
	// ========================================================================================================

	public Collection<ConfigAttribute> getAttributes(Method method, Class<?> targetClass) {
		DefaultCacheKey cacheKey = new DefaultCacheKey(method, targetClass);
		synchronized (attributeCache) {
			Collection<ConfigAttribute> cached = attributeCache.get(cacheKey);
			// Check for canonical value indicating there is no config attribute,

			if (cached != null) {
				return cached;
			}

			// No cached value, so query the sources to find a result
			Collection<ConfigAttribute> attributes = null;
			attributes = methodSecurityMetadataSource.getAttributes(method, targetClass);

			// Put it in the cache.
			if (attributes == null || attributes.isEmpty()) {
				this.attributeCache.put(cacheKey, NULL_CONFIG_ATTRIBUTE);
				return NULL_CONFIG_ATTRIBUTE;
			}

			if (logger.isDebugEnabled()) {
				logger.debug("Caching method [" + cacheKey + "] with attributes "
						+ attributes);
			}

			this.attributeCache.put(cacheKey, attributes);

			return attributes;
		}
	}

	@Override
	public Collection<ConfigAttribute> getAllConfigAttributes() {
		Set<ConfigAttribute> set = new HashSet<>();
		Collection<ConfigAttribute> attrs = methodSecurityMetadataSource.getAllConfigAttributes();
		if (attrs != null) {
			set.addAll(attrs);
		}
		return set;
	}

	public MethodSecurityMetadataSource getMethodSecurityMetadataSource() {
		return methodSecurityMetadataSource;
	}

	// ~ Inner Classes
	// ==================================================================================================

	private static class DefaultCacheKey {
		private final Method method;
		private final Class<?> targetClass;

		public DefaultCacheKey(Method method, Class<?> targetClass) {
			this.method = method;
			this.targetClass = targetClass;
		}

		@Override
		public boolean equals(Object other) {
			DefaultCacheKey otherKey = (DefaultCacheKey) other;
			return (this.method.equals(otherKey.method) && ObjectUtils.nullSafeEquals(
					this.targetClass, otherKey.targetClass));
		}

		@Override
		public int hashCode() {
			return this.method.hashCode() * 21
					+ (this.targetClass != null ? this.targetClass.hashCode() : 0);
		}

		@Override
		public String toString() {
			return "CacheKey[" + (targetClass == null ? "-" : targetClass.getName())
					+ "; " + method + "]";
		}
	}
}
