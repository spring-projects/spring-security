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

package org.springframework.security.access.prepost;

import org.jspecify.annotations.Nullable;

import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.security.authorization.AuthorizationManager;

/**
 * @author Luke Taylor
 * @since 3.0
 * @see org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor
 * @see org.springframework.security.authorization.method.AuthorizationManagerAfterMethodInterceptor
 * @deprecated Use delegation with {@link AuthorizationManager}
 */
@Deprecated
public interface PrePostInvocationAttributeFactory extends AopInfrastructureBean {

	PreInvocationAttribute createPreInvocationAttribute(@Nullable String preFilterAttribute,
			@Nullable String filterObject, @Nullable String preAuthorizeAttribute);

	PostInvocationAttribute createPostInvocationAttribute(@Nullable String postFilterAttribute,
			@Nullable String postAuthorizeAttribute);

}
