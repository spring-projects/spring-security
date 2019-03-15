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
package org.springframework.security.config.annotation.web.configuration.sec2377;

import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.web.configuration.sec2377.a.*
import org.springframework.security.config.annotation.web.configuration.sec2377.b.*
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext

public class Sec2377Tests extends BaseSpringSpec {

    def "SEC-2377: Error reporting with multiple EnableWebSecurity from other packages"() {
        when:
            AnnotationConfigWebApplicationContext parent = new AnnotationConfigWebApplicationContext()
            parent.register(Sec2377AConfig)
            parent.refresh()

            AnnotationConfigWebApplicationContext child = new AnnotationConfigWebApplicationContext()
            child.register(Sec2377BConfig)
            child.parent = parent
            child.refresh()
        then:
            noExceptionThrown();
    }
}
