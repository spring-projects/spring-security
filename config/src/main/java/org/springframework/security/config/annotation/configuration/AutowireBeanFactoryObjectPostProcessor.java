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
package org.springframework.security.config.annotation.configuration;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.Aware;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.util.Assert;

/**
 * Allows registering Objects to participate with an
 * {@link AutowireCapableBeanFactory}'s post processing of {@link Aware}
 * methods, {@link InitializingBean#afterPropertiesSet()}, and
 * {@link DisposableBean#destroy()}.
 *
 * @author Rob Winch
 * @since 3.2
 */
final class AutowireBeanFactoryObjectPostProcessor implements ObjectPostProcessor<Object>, DisposableBean {
    private final Log logger = LogFactory.getLog(getClass());
    private final AutowireCapableBeanFactory autowireBeanFactory;
    private final List<DisposableBean> disposableBeans = new ArrayList<DisposableBean>();

    public AutowireBeanFactoryObjectPostProcessor(
            AutowireCapableBeanFactory autowireBeanFactory) {
        Assert.notNull(autowireBeanFactory, "autowireBeanFactory cannot be null");
        this.autowireBeanFactory = autowireBeanFactory;
    }

    /* (non-Javadoc)
     * @see org.springframework.security.config.annotation.web.Initializer#initialize(java.lang.Object)
     */
    @SuppressWarnings("unchecked")
    public <T> T postProcess(T object) {
        if(object == null) {
            return null;
        }
        T result = null;
        try {
            result = (T) autowireBeanFactory.initializeBean(object, object.toString());
        } catch (RuntimeException e) {
            Class<?> type = object.getClass();
            throw new RuntimeException("Could not postProcess " + object + " of type " + type, e);
        }
        if(result instanceof DisposableBean) {
            disposableBeans.add((DisposableBean) result);
        }
        return result;
    }

    /* (non-Javadoc)
     * @see org.springframework.beans.factory.DisposableBean#destroy()
     */
    public void destroy() throws Exception {
        for(DisposableBean disposable : disposableBeans) {
            try {
                disposable.destroy();
            } catch(Exception error) {
                logger.error(error);
            }
        }
    }

}
