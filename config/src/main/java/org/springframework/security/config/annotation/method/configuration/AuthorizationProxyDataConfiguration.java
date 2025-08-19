/*
 * Copyright 2004-present the original author or authors.
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

import java.util.List;

import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.core.Ordered;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.SliceImpl;
import org.springframework.data.geo.GeoPage;
import org.springframework.data.geo.GeoResult;
import org.springframework.data.geo.GeoResults;
import org.springframework.security.aot.hint.SecurityHintsRegistrar;
import org.springframework.security.authorization.AuthorizationProxyFactory;
import org.springframework.security.authorization.method.AuthorizationAdvisorProxyFactory;
import org.springframework.security.data.aot.hint.AuthorizeReturnObjectDataHintsRegistrar;

@Configuration(proxyBeanMethods = false)
final class AuthorizationProxyDataConfiguration implements AopInfrastructureBean {

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static SecurityHintsRegistrar authorizeReturnObjectDataHintsRegistrar(AuthorizationProxyFactory proxyFactory) {
		return new AuthorizeReturnObjectDataHintsRegistrar(proxyFactory);
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	DataTargetVisitor dataTargetVisitor() {
		return new DataTargetVisitor();
	}

	static final class DataTargetVisitor implements AuthorizationAdvisorProxyFactory.TargetVisitor, Ordered {

		private static final int DEFAULT_ORDER = 200;

		@Override
		public Object visit(AuthorizationAdvisorProxyFactory proxyFactory, Object target) {
			if (target instanceof GeoResults<?> geoResults) {
				return new GeoResults<>(proxyFactory.proxy(geoResults.getContent()), geoResults.getAverageDistance());
			}
			if (target instanceof GeoResult<?> geoResult) {
				return new GeoResult<>(proxyFactory.proxy(geoResult.getContent()), geoResult.getDistance());
			}
			if (target instanceof GeoPage<?> geoPage) {
				GeoResults<?> results = new GeoResults<>(proxyFactory.proxy(geoPage.getContent()),
						geoPage.getAverageDistance());
				return new GeoPage<>(results, geoPage.getPageable(), geoPage.getTotalElements());
			}
			if (target instanceof PageImpl<?> page) {
				List<?> content = proxyFactory.proxy(page.getContent());
				return new PageImpl<>(content, page.getPageable(), page.getTotalElements());
			}
			if (target instanceof SliceImpl<?> slice) {
				List<?> content = proxyFactory.proxy(slice.getContent());
				return new SliceImpl<>(content, slice.getPageable(), slice.hasNext());
			}
			return null;
		}

		@Override
		public int getOrder() {
			return DEFAULT_ORDER;
		}

	}

}
