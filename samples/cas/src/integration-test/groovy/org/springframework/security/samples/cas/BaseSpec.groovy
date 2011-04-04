/*
 * Copyright 2011 the original author or authors.
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
package org.springframework.security.samples.cas;

import java.io.File;

import geb.spock.*


/**
 * Base test for Geb testing.
 *
 * @author Rob Winch
 */
class BaseSpec extends GebReportingSpec {

    /**
     * All relative urls will be interpreted against this. The host can change based upon a system property. This
     * allows for the port to be randomly selected from available ports for CI.
     */
    String getBaseUrl() {
        def host = System.getProperty('cas.service.host', 'localhost:8443')
        "https://${host}/cas-sample/"
    }

    /**
     * Write out responses and screenshots here.
     */
    File getReportDir() {
        new File('build/geb-reports')
    }
}