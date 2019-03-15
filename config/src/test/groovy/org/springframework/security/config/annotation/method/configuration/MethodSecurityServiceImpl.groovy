/*
 * Copyright 2002-2013 the original author or authors.
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

import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder

/**
 *
 * @author Rob Winch
 *
 */
public class MethodSecurityServiceImpl implements MethodSecurityService {

    @Override
    public String preAuthorize() {
        return null;
    }

    @Override
    public String secured() {
        return null;
    }

    @Override
    public String securedUser() {
        return null;
    }

    @Override
    public String jsr250() {
        return null;
    }

    @Override
    public String jsr250PermitAll() {
        return null;
    }

    @Override
    public Authentication runAs() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    @Override
    public String preAuthorizePermitAll() {
        return null;
    }

    @Override
    public String hasPermission(String object) {
        return null;
    }

    @Override
    public String postHasPermission(String object) {
        return null;
    }

    @Override
    public String postAnnotation(String object) {
        return null;
    }
}
