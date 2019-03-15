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
package org.springframework.security.core.authority.mapping;

import org.springframework.security.core.GrantedAuthority;

import java.util.*;

/**
 * Mapping interface which can be injected into the authentication layer to convert the
 * authorities loaded from storage into those which will be used in the
 * {@code Authentication} object.
 *
 * @author Luke Taylor
 */
public interface GrantedAuthoritiesMapper {
	Collection<? extends GrantedAuthority> mapAuthorities(
			Collection<? extends GrantedAuthority> authorities);
}
