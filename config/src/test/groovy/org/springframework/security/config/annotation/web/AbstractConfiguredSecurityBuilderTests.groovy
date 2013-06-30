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
package org.springframework.security.config.annotation.web

import org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityConfigurer
import org.springframework.security.config.annotation.SecurityConfigurerAdapter
import org.springframework.test.util.ReflectionTestUtils

import spock.lang.Specification

/**
 * @author Rob Winch
 *
 */
class AbstractConfiguredSecurityBuilderTests extends Specification {

    ConcreteAbstractConfiguredBuilder builder = new ConcreteAbstractConfiguredBuilder()

    def "Null ObjectPostProcessor rejected"() {
        when:
            new ConcreteAbstractConfiguredBuilder(null)
        then:
            thrown(IllegalArgumentException)
        when:
            builder.objectPostProcessor(null);
        then:
            thrown(IllegalArgumentException)
    }

    def "apply null is rejected"() {
        when:
            builder.apply(null)
        then:
            thrown(IllegalArgumentException)
    }

    def "Duplicate configurer is removed"() {
        when:
            builder.apply(new ConcreteConfigurer())
            builder.apply(new ConcreteConfigurer())
        then:
            ReflectionTestUtils.getField(builder,"configurers").size() == 1
    }

    def "build twice fails"() {
        setup:
            builder.build()
        when:
            builder.build()
        then:
            thrown(IllegalStateException)
    }

    def "getObject before build fails"() {
        when:
            builder.getObject()
        then:
            thrown(IllegalStateException)
    }

    def "Configurer.init can apply another configurer"() {
        setup:
            DelegateConfigurer.CONF = Mock(SecurityConfigurerAdapter)
        when:
            builder.apply(new DelegateConfigurer())
            builder.build()
        then:
            1 * DelegateConfigurer.CONF.init(builder)
            1 * DelegateConfigurer.CONF.configure(builder)
    }

    def "getConfigurer with multi fails"() {
        setup:
            ConcreteAbstractConfiguredBuilder builder = new ConcreteAbstractConfiguredBuilder(ObjectPostProcessor.QUIESCENT_POSTPROCESSOR, true)
            builder.apply(new DelegateConfigurer())
            builder.apply(new DelegateConfigurer())
        when:
            builder.getConfigurer(DelegateConfigurer)
        then: "Fail due to trying to obtain a single DelegateConfigurer and multiple are provided"
            thrown(IllegalStateException)
    }

    def "removeConfigurer with multi fails"() {
        setup:
            ConcreteAbstractConfiguredBuilder builder = new ConcreteAbstractConfiguredBuilder(ObjectPostProcessor.QUIESCENT_POSTPROCESSOR, true)
            builder.apply(new DelegateConfigurer())
            builder.apply(new DelegateConfigurer())
        when:
            builder.removeConfigurer(DelegateConfigurer)
        then: "Fail due to trying to remove and obtain a single DelegateConfigurer and multiple are provided"
            thrown(IllegalStateException)
    }

    def "removeConfigurers with multi"() {
        setup:
            DelegateConfigurer c1 = new DelegateConfigurer()
            DelegateConfigurer c2 = new DelegateConfigurer()
            ConcreteAbstractConfiguredBuilder builder = new ConcreteAbstractConfiguredBuilder(ObjectPostProcessor.QUIESCENT_POSTPROCESSOR, true)
            builder.apply(c1)
            builder.apply(c2)
        when:
            def result = builder.removeConfigurers(DelegateConfigurer)
        then:
            result.size() == 2
            result.contains(c1)
            result.contains(c2)
            builder.getConfigurers(DelegateConfigurer).empty
    }

    def "getConfigurers with multi"() {
        setup:
            DelegateConfigurer c1 = new DelegateConfigurer()
            DelegateConfigurer c2 = new DelegateConfigurer()
            ConcreteAbstractConfiguredBuilder builder = new ConcreteAbstractConfiguredBuilder(ObjectPostProcessor.QUIESCENT_POSTPROCESSOR, true)
            builder.apply(c1)
            builder.apply(c2)
        when:
            def result = builder.getConfigurers(DelegateConfigurer)
        then:
            result.size() == 2
            result.contains(c1)
            result.contains(c2)
            builder.getConfigurers(DelegateConfigurer).size() == 2
    }

    private static class DelegateConfigurer extends SecurityConfigurerAdapter<Object, ConcreteAbstractConfiguredBuilder> {
        private static SecurityConfigurer<Object, ConcreteAbstractConfiguredBuilder> CONF;

        @Override
        public void init(ConcreteAbstractConfiguredBuilder builder)
                throws Exception {
            builder.apply(CONF);
        }
    }

    private static class ConcreteConfigurer extends SecurityConfigurerAdapter<Object, ConcreteAbstractConfiguredBuilder> { }

    private static class ConcreteAbstractConfiguredBuilder extends AbstractConfiguredSecurityBuilder<Object, ConcreteAbstractConfiguredBuilder> {

        public ConcreteAbstractConfiguredBuilder() {
        }

        public ConcreteAbstractConfiguredBuilder(ObjectPostProcessor<Object> objectPostProcessor) {
            super(objectPostProcessor);
        }

        public ConcreteAbstractConfiguredBuilder(ObjectPostProcessor<Object> objectPostProcessor, boolean allowMulti) {
            super(objectPostProcessor,allowMulti);
        }

        public Object performBuild() throws Exception {
            return "success";
        }
    }

}
