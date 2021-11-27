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
 * The Spring Security ACL package which implements instance-based security for domain
 * objects.
 * <p>
 * Consider using the annotation based approach ({@code @PreAuthorize},
 * {@code @PostFilter} annotations) combined with a
 * {@link org.springframework.security.acls.AclPermissionEvaluator} in preference to the
 * older and more verbose attribute/voter/after-invocation approach from versions before
 * Spring Security 3.0.
 */
package org.springframework.security.acls;
