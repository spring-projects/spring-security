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

import java.util.Collections;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.LocalVariableTableParameterNameDiscoverer;
import org.springframework.core.ParameterNameDiscoverer;
import org.springframework.core.PrioritizedParameterNameDiscoverer;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;


/**
 * Spring Security's default {@link ParameterNameDiscoverer} which tries a
 * number of {@link ParameterNameDiscoverer} depending on what is found on the
 * classpath.
 *
 * <ul>
 * <li>If Spring 4 is on the classpath, then DefaultParameterNameDiscoverer is
 * added. This attempts to use JDK 8 information first and falls back to
 * {@link LocalVariableTableParameterNameDiscoverer}.</li>
 * <li>If Spring 4 is not on the classpath, then
 * {@link LocalVariableTableParameterNameDiscoverer} is added directly.</li>
 * </ul>
 *
 * @author Rob Winch
 * @since 3.2
 */
public class DefaultSecurityParameterNameDiscoverer extends
        PrioritizedParameterNameDiscoverer {

    private final Log logger = LogFactory.getLog(getClass());

    private static final String DEFAULT_PARAMETER_NAME_DISCOVERER_CLASSNAME =
            "org.springframework.core.DefaultParameterNameDiscoverer";
    private static final boolean DEFAULT_PARAM_DISCOVERER_PRESENT =
            ClassUtils.isPresent(DEFAULT_PARAMETER_NAME_DISCOVERER_CLASSNAME, DefaultSecurityParameterNameDiscoverer.class.getClassLoader());

    /**
     * Creates a new instance with only the default
     * {@link ParameterNameDiscoverer} instances.
     */
    public DefaultSecurityParameterNameDiscoverer() {
        this(Collections.<ParameterNameDiscoverer>emptyList());
    }

    /**
     * Creates a new instance that first tries the passed in {@link ParameterNameDiscoverer} instances.
     * @param parameterNameDiscovers the {@link ParameterNameDiscoverer} before trying the defaults. Cannot be null.
     */
    @SuppressWarnings("unchecked")
    public DefaultSecurityParameterNameDiscoverer(List<? extends ParameterNameDiscoverer> parameterNameDiscovers) {
        Assert.notNull(parameterNameDiscovers, "parameterNameDiscovers cannot be null");
        for(ParameterNameDiscoverer discover : parameterNameDiscovers) {
            addDiscoverer(discover);
        }
        if (DEFAULT_PARAM_DISCOVERER_PRESENT) {
            try {
                Class<? extends ParameterNameDiscoverer> paramNameDiscoverClass = (Class<? extends ParameterNameDiscoverer>) ClassUtils
                        .forName(DEFAULT_PARAMETER_NAME_DISCOVERER_CLASSNAME,
                                getClass().getClassLoader());
                addDiscoverer(paramNameDiscoverClass.newInstance());
            } catch (Exception e) {
                logger.warn(
                        "Could not use "
                                + DEFAULT_PARAMETER_NAME_DISCOVERER_CLASSNAME
                                + ". Falling back to LocalVariableTableParameterNameDiscoverer.", e);
                addDiscoverer(new LocalVariableTableParameterNameDiscoverer());
            }
        } else {
            addDiscoverer(new LocalVariableTableParameterNameDiscoverer());
        }
    }
}