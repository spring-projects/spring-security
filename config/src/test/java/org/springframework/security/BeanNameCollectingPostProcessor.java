package org.springframework.security;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;

import java.util.*;

/**
 * @author Luke Taylor
 */
public class BeanNameCollectingPostProcessor implements BeanPostProcessor {
    Set<String> beforeInitPostProcessedBeans = new HashSet<String>();
    Set<String> afterInitPostProcessedBeans = new HashSet<String>();

    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        if (beanName != null) {
            beforeInitPostProcessedBeans.add(beanName);
        }
        return bean;
    }

    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        if (beanName != null) {
            afterInitPostProcessedBeans.add(beanName);
        }
        return bean;
    }
}
