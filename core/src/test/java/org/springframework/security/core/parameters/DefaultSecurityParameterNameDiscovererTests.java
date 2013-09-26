/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.core.parameters;

import static org.fest.assertions.Assertions.assertThat;

import java.util.Arrays;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.springframework.core.DefaultParameterNameDiscoverer;
import org.springframework.core.LocalVariableTableParameterNameDiscoverer;
import org.springframework.core.ParameterNameDiscoverer;
import org.springframework.test.util.ReflectionTestUtils;

/**
 *
 * @author Rob Winch
 * @since 3.2
 */
@SuppressWarnings("unchecked")
public class DefaultSecurityParameterNameDiscovererTests {
    private DefaultSecurityParameterNameDiscoverer discoverer;

    @Before
    public void setup() {
        discoverer = new DefaultSecurityParameterNameDiscoverer();
    }

    @Test
    public void constructorDefault() {
        List<ParameterNameDiscoverer> discoverers = (List<ParameterNameDiscoverer>) ReflectionTestUtils
                .getField(discoverer, "parameterNameDiscoverers");
        assertThat(discoverers.size()).isEqualTo(1);
        assertThat(discoverers.get(0)).isInstanceOf(
                DefaultParameterNameDiscoverer.class);
    }

    @Test
    public void constructorDiscoverers() {
        discoverer = new DefaultSecurityParameterNameDiscoverer(Arrays.asList(new LocalVariableTableParameterNameDiscoverer()));

        List<ParameterNameDiscoverer> discoverers = (List<ParameterNameDiscoverer>) ReflectionTestUtils
                .getField(discoverer, "parameterNameDiscoverers");

        assertThat(discoverers.size()).isEqualTo(2);
        assertThat(discoverers.get(0)).isInstanceOf(
                LocalVariableTableParameterNameDiscoverer.class);
        assertThat(discoverers.get(1)).isInstanceOf(
                DefaultParameterNameDiscoverer.class);
    }
}