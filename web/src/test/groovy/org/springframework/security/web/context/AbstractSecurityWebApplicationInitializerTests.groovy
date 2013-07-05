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
package org.springframework.security.web.context;

import java.util.EnumSet;

import javax.servlet.DispatcherType;
import javax.servlet.Filter;
import javax.servlet.FilterRegistration;
import javax.servlet.ServletContext;

import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.filter.DelegatingFilterProxy;

import spock.lang.Specification

/**
 * @author Rob Winch
 *
 */
class AbstractSecurityWebApplicationInitializerTests extends Specification {

    def defaults() {
        setup:
            ServletContext context = Mock()
            FilterRegistration.Dynamic registration = Mock()
        when:
            new AbstractSecurityWebApplicationInitializer(){}.onStartup(context)
        then:
            1 * context.addFilter("springSecurityFilterChain", {DelegatingFilterProxy f -> f.targetBeanName == "springSecurityFilterChain" && f.contextAttribute == null}) >> registration
            1 * registration.addMappingForUrlPatterns(EnumSet.of(DispatcherType.REQUEST, DispatcherType.ERROR), false, "/*");
            1 * registration.setAsyncSupported(true)
            0 * context.addListener(_)
    }

    def "enableHttpSessionEventPublisher() = true"() {
        setup:
            ServletContext context = Mock()
            FilterRegistration.Dynamic registration = Mock()
        when:
            new AbstractSecurityWebApplicationInitializer(){
                protected boolean enableHttpSessionEventPublisher() {
                    return true;
                }
            }.onStartup(context)
        then:
            1 * context.addFilter("springSecurityFilterChain", {DelegatingFilterProxy f -> f.targetBeanName == "springSecurityFilterChain" && f.contextAttribute == null}) >> registration
            1 * registration.addMappingForUrlPatterns(EnumSet.of(DispatcherType.REQUEST, DispatcherType.ERROR), false, "/*");
            1 * registration.setAsyncSupported(true)
            1 * context.addListener(HttpSessionEventPublisher)
    }

    def "custom getSecurityDispatcherTypes()"() {
        setup:
            ServletContext context = Mock()
            FilterRegistration.Dynamic registration = Mock()
        when:
            new AbstractSecurityWebApplicationInitializer(){
                protected EnumSet<DispatcherType> getSecurityDispatcherTypes() {
                    return EnumSet.of(DispatcherType.REQUEST, DispatcherType.ERROR, DispatcherType.FORWARD);
                }
            }.onStartup(context)
        then:
            1 * context.addFilter("springSecurityFilterChain", {DelegatingFilterProxy f -> f.targetBeanName == "springSecurityFilterChain" && f.contextAttribute == null}) >> registration
            1 * registration.addMappingForUrlPatterns(EnumSet.of(DispatcherType.REQUEST, DispatcherType.ERROR, DispatcherType.FORWARD), false, "/*");
            1 * registration.setAsyncSupported(true)
            0 * context.addListener(_)
    }

    def "custom getDispatcherWebApplicationContextSuffix"() {
        setup:
            ServletContext context = Mock()
            FilterRegistration.Dynamic registration = Mock()
        when:
            new AbstractSecurityWebApplicationInitializer(){
                protected String getDispatcherWebApplicationContextSuffix() {
                    return "dispatcher"
                }
            }.onStartup(context)
        then:
            1 * context.addFilter("springSecurityFilterChain", {DelegatingFilterProxy f -> f.targetBeanName == "springSecurityFilterChain" && f.contextAttribute == "org.springframework.web.servlet.FrameworkServlet.CONTEXT.dispatcher"}) >> registration
            1 * registration.addMappingForUrlPatterns(EnumSet.of(DispatcherType.REQUEST, DispatcherType.ERROR), false, "/*");
            1 * registration.setAsyncSupported(true)
            0 * context.addListener(_)
    }

    def "springSecurityFilterChain already registered"() {
        setup:
            ServletContext context = Mock()
            FilterRegistration.Dynamic registration = Mock()
        when:
            new AbstractSecurityWebApplicationInitializer(){}.onStartup(context)
        then:
            1 * context.addFilter("springSecurityFilterChain", {DelegatingFilterProxy f -> f.targetBeanName == "springSecurityFilterChain" && f.contextAttribute == null}) >> null
            IllegalStateException success = thrown()
            success.message == "Duplicate Filter registration for 'springSecurityFilterChain'. Check to ensure the Filter is only configured once."
    }

    def "insertFilters"() {
        setup:
            Filter filter1 = Mock()
            Filter filter2 = Mock()
            ServletContext context = Mock()
            FilterRegistration.Dynamic registration = Mock()
        when:
            new AbstractSecurityWebApplicationInitializer(){
                protected void afterSpringSecurityFilterChain(ServletContext servletContext) {
                    insertFilters(context, filter1, filter2);
                }
            }.onStartup(context)
        then:
            1 * context.addFilter("springSecurityFilterChain", {DelegatingFilterProxy f -> f.targetBeanName == "springSecurityFilterChain" && f.contextAttribute == null}) >> registration
            3 * registration.addMappingForUrlPatterns(EnumSet.of(DispatcherType.REQUEST, DispatcherType.ERROR), false, "/*");
            3 * registration.setAsyncSupported(true)
            0 * context.addListener(_)
            1 * context.addFilter(_, filter1) >> registration
            1 * context.addFilter(_, filter2) >> registration
    }

    def "insertFilters already registered"() {
        setup:
            Filter filter1 = Mock()
            ServletContext context = Mock()
            FilterRegistration.Dynamic registration = Mock()
        when:
            new AbstractSecurityWebApplicationInitializer(){
                protected void afterSpringSecurityFilterChain(ServletContext servletContext) {
                    insertFilters(context, filter1);
                }
            }.onStartup(context)
        then:
            1 * context.addFilter("springSecurityFilterChain", {DelegatingFilterProxy f -> f.targetBeanName == "springSecurityFilterChain" && f.contextAttribute == null}) >> registration
            1 * registration.addMappingForUrlPatterns(EnumSet.of(DispatcherType.REQUEST, DispatcherType.ERROR), false, "/*");
            1 * context.addFilter(_, filter1) >> null
            IllegalStateException success = thrown()
            success.message == "Duplicate Filter registration for 'filter'. Check to ensure the Filter is only configured once."
    }

    def "insertFilters no filters"() {
        setup:
            ServletContext context = Mock()
            FilterRegistration.Dynamic registration = Mock()
        when:
            new AbstractSecurityWebApplicationInitializer(){
                protected void afterSpringSecurityFilterChain(ServletContext servletContext) {
                    insertFilters(context);
                }
            }.onStartup(context)
        then:
            1 * context.addFilter("springSecurityFilterChain", {DelegatingFilterProxy f -> f.targetBeanName == "springSecurityFilterChain" && f.contextAttribute == null}) >> registration
            IllegalArgumentException success = thrown()
            success.message == "filters cannot be null or empty"
    }

    def "insertFilters filters with null"() {
        setup:
            Filter filter1 = Mock()
            ServletContext context = Mock()
            FilterRegistration.Dynamic registration = Mock()
        when:
            new AbstractSecurityWebApplicationInitializer(){
                protected void afterSpringSecurityFilterChain(ServletContext servletContext) {
                    insertFilters(context,  filter1, null);
                }
            }.onStartup(context)
        then:
            2 * context.addFilter(_, _) >> registration
            IllegalArgumentException success = thrown()
            success.message == "filters cannot contain null values. Got [Mock for type 'Filter' named 'filter1', null]"
    }

    def "appendFilters"() {
        setup:
            Filter filter1 = Mock()
            Filter filter2 = Mock()
            ServletContext context = Mock()
            FilterRegistration.Dynamic registration = Mock()
        when:
            new AbstractSecurityWebApplicationInitializer(){
                protected void afterSpringSecurityFilterChain(ServletContext servletContext) {
                    appendFilters(context,filter1, filter2);
                }
            }.onStartup(context)
        then:
            1 * context.addFilter("springSecurityFilterChain", {DelegatingFilterProxy f -> f.targetBeanName == "springSecurityFilterChain" && f.contextAttribute == null}) >> registration
            1 * registration.addMappingForUrlPatterns(EnumSet.of(DispatcherType.REQUEST, DispatcherType.ERROR), false, "/*");
            2 * registration.addMappingForUrlPatterns(EnumSet.of(DispatcherType.REQUEST, DispatcherType.ERROR), true, "/*");
            3 * registration.setAsyncSupported(true)
            0 * context.addListener(_)
            1 * context.addFilter(_, filter1) >> registration
            1 * context.addFilter(_, filter2) >> registration
    }

    def "appendFilters already registered"() {
        setup:
            Filter filter1 = Mock()
            ServletContext context = Mock()
            FilterRegistration.Dynamic registration = Mock()
        when:
            new AbstractSecurityWebApplicationInitializer(){
                protected void afterSpringSecurityFilterChain(ServletContext servletContext) {
                    appendFilters(context, filter1);
                }
            }.onStartup(context)
        then:
            1 * context.addFilter("springSecurityFilterChain", {DelegatingFilterProxy f -> f.targetBeanName == "springSecurityFilterChain" && f.contextAttribute == null}) >> registration
            1 * registration.addMappingForUrlPatterns(EnumSet.of(DispatcherType.REQUEST, DispatcherType.ERROR), false, "/*");
            1 * context.addFilter(_, filter1) >> null
            IllegalStateException success = thrown()
            success.message == "Duplicate Filter registration for 'filter'. Check to ensure the Filter is only configured once."
    }

    def "appendFilters no filters"() {
        setup:
            ServletContext context = Mock()
            FilterRegistration.Dynamic registration = Mock()
        when:
            new AbstractSecurityWebApplicationInitializer(){
                protected void afterSpringSecurityFilterChain(ServletContext servletContext) {
                    appendFilters(context);
                }
            }.onStartup(context)
        then:
            1 * context.addFilter("springSecurityFilterChain", {DelegatingFilterProxy f -> f.targetBeanName == "springSecurityFilterChain" && f.contextAttribute == null}) >> registration
            IllegalArgumentException success = thrown()
            success.message == "filters cannot be null or empty"
    }

    def "appendFilters filters with null"() {
        setup:
            Filter filter1 = Mock()
            ServletContext context = Mock()
            FilterRegistration.Dynamic registration = Mock()
        when:
            new AbstractSecurityWebApplicationInitializer(){
                protected void afterSpringSecurityFilterChain(ServletContext servletContext) {
                    appendFilters(context,  filter1, null);
                }
            }.onStartup(context)
        then:
            2 * context.addFilter(_, _) >> registration
            IllegalArgumentException success = thrown()
            success.message == "filters cannot contain null values. Got [Mock for type 'Filter' named 'filter1', null]"
    }

    def "DEFAULT_FILTER_NAME == springSecurityFilterChain"() {
        expect:
            AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME == "springSecurityFilterChain"
    }
}
