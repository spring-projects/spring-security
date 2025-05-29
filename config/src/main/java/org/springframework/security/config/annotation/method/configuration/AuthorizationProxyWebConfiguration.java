/*
 * Copyright 2002-2025 the original author or authors.
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
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.method.AuthorizationAdvisorProxyFactory;
import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.mvc.support.DefaultHandlerExceptionResolver;

@Configuration
class AuthorizationProxyWebConfiguration implements WebMvcConfigurer {

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	AuthorizationAdvisorProxyFactory.TargetVisitor webTargetVisitor() {
		return new WebTargetVisitor();
	}

	@Override
	public void extendHandlerExceptionResolvers(List<HandlerExceptionResolver> resolvers) {
		for (int i = 0; i < resolvers.size(); i++) {
			HandlerExceptionResolver resolver = resolvers.get(i);
			if (resolver instanceof DefaultHandlerExceptionResolver) {
				resolvers.add(i, new AccessDeniedExceptionResolver());
				return;
			}
		}
		resolvers.add(new AccessDeniedExceptionResolver());
	}

	static class WebTargetVisitor implements AuthorizationAdvisorProxyFactory.TargetVisitor {

		@Override
		public Object visit(AuthorizationAdvisorProxyFactory proxyFactory, Object target) {
			if (target instanceof ResponseEntity<?> entity) {
				return new ResponseEntity<>(proxyFactory.proxy(entity.getBody()), entity.getHeaders(),
						entity.getStatusCode());
			}
			if (target instanceof HttpEntity<?> entity) {
				return new HttpEntity<>(proxyFactory.proxy(entity.getBody()), entity.getHeaders());
			}
			if (target instanceof ModelAndView mav) {
				View view = mav.getView();
				String viewName = mav.getViewName();
				Map<String, Object> model = proxyFactory.proxy(mav.getModel());
				ModelAndView proxied = (view != null) ? new ModelAndView(view, model)
						: new ModelAndView(viewName, model);
				proxied.setStatus(mav.getStatus());
				return proxied;
			}
			return null;
		}

	}

	static class AccessDeniedExceptionResolver implements HandlerExceptionResolver {

		final ThrowableAnalyzer throwableAnalyzer = new ThrowableAnalyzer();

		@Override
		public ModelAndView resolveException(HttpServletRequest request, HttpServletResponse response, Object handler,
				Exception ex) {
			Throwable[] causeChain = this.throwableAnalyzer.determineCauseChain(ex);
			Throwable accessDeniedException = this.throwableAnalyzer
				.getFirstThrowableOfType(AccessDeniedException.class, causeChain);
			if (accessDeniedException != null) {
				return new ModelAndView((model, req, res) -> {
					throw ex;
				});
			}
			return null;
		}

	}

}
