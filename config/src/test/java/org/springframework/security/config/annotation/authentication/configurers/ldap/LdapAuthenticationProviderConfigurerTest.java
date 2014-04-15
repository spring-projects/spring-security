/*
 * Copyright 2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.config.annotation.authentication.configurers.ldap;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;

public class LdapAuthenticationProviderConfigurerTest {

    private LdapAuthenticationProviderConfigurer configurer;

    @Before
    public void setUp() {
        configurer = new LdapAuthenticationProviderConfigurer();
    }

    // SEC-2557
    @Test
    public void getAuthoritiesMapper() throws Exception {
        assertEquals(SimpleAuthorityMapper.class, configurer.getAuthoritiesMapper().getClass());
        configurer.authoritiesMapper(new NullAuthoritiesMapper());
        assertEquals(NullAuthoritiesMapper.class, configurer.getAuthoritiesMapper().getClass());

    }
}
