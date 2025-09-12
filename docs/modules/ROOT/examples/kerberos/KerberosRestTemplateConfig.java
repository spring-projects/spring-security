/*
 * Copyright 2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.kerberos.client.docs;

import org.springframework.security.kerberos.client.KerberosRestTemplate;

public class KerberosRestTemplateConfig {

//tag::snippetA[]
    public void doWithTicketCache() {
        KerberosRestTemplate restTemplate =
                new KerberosRestTemplate();
        restTemplate.getForObject("http://neo.example.org:8080/hello", String.class);
    }
//end::snippetA[]

//tag::snippetB[]
    public void doWithKeytabFile() {
        KerberosRestTemplate restTemplate =
                new KerberosRestTemplate("/tmp/user2.keytab", "user2@EXAMPLE.ORG");
        restTemplate.getForObject("http://neo.example.org:8080/hello", String.class);
    }
//end::snippetB[]

}
