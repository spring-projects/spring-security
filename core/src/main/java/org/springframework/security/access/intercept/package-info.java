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
/**
 * Abstract level security interception classes which are responsible for enforcing the
 * configured security constraints for a secure object.
 * <p>
 * A <i>secure object</i> is a term frequently used throughout the security
 * system. It does <b>not</b> refer to a business object that is being
 * secured, but instead refers to some infrastructure object that can have
 * security facilities provided for it by Spring Security.
 * For example, one secure object would be <code>MethodInvocation</code>,
 * whilst another would be HTTP
 * {@code org.springframework.security.web.FilterInvocation}. Note these are
 * infrastructure objects and their design allows them to represent a large
 * variety of actual resources that might need to be secured, such as business
 * objects or HTTP request URLs.
 * <p>Each secure object typically has its own interceptor package.
 * Each package usually includes a concrete security interceptor (which subclasses
 * {@link org.springframework.security.access.intercept.AbstractSecurityInterceptor}) and an
 * appropriate {@link org.springframework.security.access.SecurityMetadataSource}
 * for the type of resources the secure object represents.
 */
package org.springframework.security.access.intercept;

