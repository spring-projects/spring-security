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
package org.springframework.security.samples.cas

import org.apache.commons.httpclient.HttpClient
import org.apache.commons.httpclient.methods.GetMethod
import org.jasig.cas.client.jaas.CasLoginModule;
import org.jasig.cas.client.proxy.Cas20ProxyRetriever
import org.springframework.security.samples.cas.pages.*

import spock.lang.*


/**
 * Tests authenticating to the CAS Sample application using Proxy Tickets. Geb is used to authenticate the {@link JettyCasService}
 * to the CAS Server in order to obtain the Ticket Granting Ticket. Afterwards HttpClient is used for accessing the CAS Sample application
 * using Proxy Tickets obtained using the Proxy Granting Ticket.
 *
 * @author Rob Winch
 */
@Stepwise
class CasSampleProxySpec extends BaseSpec {
    HttpClient client = new HttpClient()
    @Shared String casServerUrl = LoginPage.url.replaceFirst('/login','')
    @Shared JettyCasService service = new JettyCasService().init(casServerUrl)
    @Shared Cas20ProxyRetriever retriever = new Cas20ProxyRetriever(casServerUrl,'UTF-8')
    @Shared String pt

    def cleanupSpec() {
        service.stop()
    }

    def 'access secure page succeeds with ROLE_USER'() {
        setup: 'Obtain a pgt for a user with ROLE_USER'
        driver.get LoginPage.url+"?service="+service.serviceUrl()
        at LoginPage
        login 'scott'
        when: 'User with ROLE_USER accesses the secure page'
        def content = getSecured(getBaseUrl()+SecurePage.url).responseBodyAsString
        then: 'The secure page is returned'
        content.contains('<h1>Secure Page</h1>')
    }

    def 'access proxy ticket sample succeeds with ROLE_USER'() {
        when: 'a proxy ticket is used to create another proxy ticket'
        def content = getSecured(getBaseUrl()+ProxyTicketSamplePage.url).responseBodyAsString
        then: 'The proxy ticket sample page is returned'
        content.contains('<h1>Secure Page using a Proxy Ticket</h1>')
    }

    def 'access extremely secure page with ROLE_USER is denied'() {
        when: 'User with ROLE_USER accesses the extremely secure page'
        GetMethod method = getSecured(getBaseUrl()+ExtremelySecurePage.url)
        then: 'access is denied'
        assert method.responseBodyAsString =~ /(?i)403.*?Denied/
        assert 403 == method.statusCode
    }

    def 'access secure page with ROLE_SUPERVISOR succeeds'() {
        setup: 'Obtain pgt for user with ROLE_SUPERVISOR'
        to LocalLogoutPage
        casServerLogout.click()
        driver.get(LoginPage.url+"?service="+service.serviceUrl())
        at LoginPage
        login 'rod'
        when: 'User with ROLE_SUPERVISOR accesses the secure page'
        def content = getSecured(getBaseUrl()+ExtremelySecurePage.url).responseBodyAsString
        then: 'The secure page is returned'
        content.contains('<h1>VERY Secure Page</h1>')
    }

    def 'access extremely secure page with ROLE_SUPERVISOR reusing pt succeeds (stateless mode works)'() {
        when: 'User with ROLE_SUPERVISOR accesses extremely secure page with used pt'
        def content = getSecured(getBaseUrl()+ExtremelySecurePage.url,pt).responseBodyAsString
        then: 'The extremely secure page is returned'
        content.contains('<h1>VERY Secure Page</h1>')
    }

    def 'access secure page with invalid proxy ticket fails'() {
        when: 'Invalid ticket is used to access secure page'
        GetMethod method = getSecured(getBaseUrl()+SecurePage.url,'invalidticket')
        then: 'Authentication fails'
        method.statusCode == 401
    }

    /**
     * Gets the result of calling a url with a proxy ticket
     * @param targetUrl the absolute url to attempt to access
     * @param pt the proxy ticket to use. Defaults to {@link #getPt(String)} with targetUrl specified for the targetUrl.
     * @return the GetMethod after calling a url with a specified proxy ticket
     */
    GetMethod getSecured(String targetUrl,String pt=getPt(targetUrl)) {
        assert pt != null
        GetMethod method = new GetMethod(targetUrl+"?ticket="+pt)
        int status = client.executeMethod(method)
        method
    }

    /**
     * Obtains a proxy ticket using the pgt from the {@link #service}.
     * @param targetService the targetService that the proxy ticket will be valid for
     * @return a proxy ticket for targetService
     */
    String getPt(String targetService) {
        assert service.pgt != null
        pt = retriever.getProxyTicketIdFor(service.pgt, targetService)
        pt
    }
}