/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation;

import org.springframework.beans.factory.Aware;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;

/**
 * Allows initialization of Objects. Typically this is used to call the
 * {@link Aware} methods, {@link InitializingBean#afterPropertiesSet()}, and
 * ensure that {@link DisposableBean#destroy()} has been invoked.
 *
 * @param <T> the bound of the types of Objects this {@link ObjectPostProcessor} supports.
 *
 * @author Rob Winch
 * @since 3.2
 */
public interface ObjectPostProcessor<T> {

    /**
     * Initialize the object possibly returning a modified instance that should
     * be used instead.
     *
     * @param object the object to initialize
     * @return the initialized version of the object
     */
    <O extends T> O postProcess(O object);

    /**
     * A do nothing implementation of the {@link ObjectPostProcessor}
     */
    ObjectPostProcessor<Object> QUIESCENT_POSTPROCESSOR =  new ObjectPostProcessor<Object>() {
        public <T> T postProcess(T object) {
            return object;
        }
    };
}
