/*
 * Copyright 2002-2018 the original author or authors.
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

import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.parameters.P;

/**
 * @author Rob Winch
 */
public interface MethodSecurityService {

	@PreAuthorize("denyAll")
	String preAuthorize();

	@Secured("ROLE_ADMIN")
	String secured();

	@Secured("ROLE_USER")
	String securedUser();

	@DenyAll
	String jsr250();

	@PermitAll
	String jsr250PermitAll();

	@Secured({ "ROLE_USER", "RUN_AS_SUPER" })
	Authentication runAs();

	@PreAuthorize("permitAll")
	String preAuthorizePermitAll();

	@PreAuthorize("!anonymous")
	void preAuthorizeNotAnonymous();

	@PreAuthorize("@authz.check(#result)")
	void preAuthorizeBean(@P("result") boolean result);

	@PreAuthorize("hasRole('ADMIN')")
	void preAuthorizeAdmin();

	@PreAuthorize("hasPermission(#object,'read')")
	String hasPermission(String object);

	@PostAuthorize("hasPermission(#object,'read')")
	String postHasPermission(String object);

	@PostAuthorize("#o?.contains('grant')")
	String postAnnotation(@P("o") String object);

}
