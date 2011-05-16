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

import java.io.IOException

import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import org.apache.commons.httpclient.HttpClient
import org.apache.commons.httpclient.methods.GetMethod;
import org.eclipse.jetty.server.Request
import org.eclipse.jetty.server.Server
import org.eclipse.jetty.server.handler.AbstractHandler
import org.eclipse.jetty.server.ssl.SslSelectChannelConnector
import org.jasig.cas.client.proxy.ProxyGrantingTicketStorage;
import org.jasig.cas.client.proxy.ProxyGrantingTicketStorageImpl;
import org.jasig.cas.client.validation.Assertion
import org.jasig.cas.client.validation.Cas20ProxyTicketValidator;

/**
 * A CAS Service that allows a PGT to be obtained. This is useful for testing use of proxy tickets.
 *
 * @author Rob Winch
 */
class JettyCasService extends Server {
    private Cas20ProxyTicketValidator validator
    private int port = availablePort()

    /**
     * The Proxy Granting Ticket. To initialize pgt, authenticate to the CAS Server with the service parameter
     * equal to {@link #serviceUrl()}.
     */
    String pgt

    /**
     * Start the CAS Service which will be available at {@link #serviceUrl()}.
     *
     * @param casServerUrl
     * @return
     */
    def init(String casServerUrl) {
        ProxyGrantingTicketStorage storage = new ProxyGrantingTicketStorageImpl()
        validator = new Cas20ProxyTicketValidator(casServerUrl)
        validator.setAcceptAnyProxy(true)
        validator.setProxyGrantingTicketStorage(storage)
        validator.setProxyCallbackUrl(absoluteUrl('callback'))

        String password = System.getProperty('javax.net.ssl.trustStorePassword','password')
        SslSelectChannelConnector ssl_connector = new SslSelectChannelConnector()
        ssl_connector.setPort(port)
        ssl_connector.setKeystore(getTrustStore())
        ssl_connector.setPassword(password)
        ssl_connector.setKeyPassword(password)
        addConnector(ssl_connector)
        setHandler(new AbstractHandler() {
            public void handle(String target, Request baseRequest,
                    HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
                def st = request.getParameter('ticket')
                if(st) {
                    JettyCasService.this.validator.validate(st, JettyCasService.this.serviceUrl())
                }
                def pgt = request.getParameter('pgtId')
                if(pgt) {
                  JettyCasService.this.pgt = pgt
                }
                response.setStatus(HttpServletResponse.SC_OK);
                baseRequest.setHandled(true);
            }
        })
        start()
        this
    }

    /**
     * Returns the absolute URL that this CAS service is available at.
     * @return
     */
    String serviceUrl() {
        absoluteUrl('service')
    }

    /**
     * Given a relative url, will provide an absolute url for this CAS Service.
     * @param relativeUrl the relative url (i.e. service, callback, etc)
     * @return
     */
    private String absoluteUrl(String relativeUrl) {
        "https://localhost:${port}/${relativeUrl}"
    }

    private static String getTrustStore() {
        String trustStoreLocation = System.getProperty('javax.net.ssl.trustStore')
        if(trustStoreLocation == null || !new File(trustStoreLocation).isFile()) {
            throw new  IllegalStateException('Could not find the trust store at path "'+trustStoreLocation+'". Specify the location using the javax.net.ssl.trustStore system property.')
        }
        trustStoreLocation
    }
    /**
     * Obtains a random available port (i.e. one that is not in use)
     * @return
     */
    private static int availablePort() {
        ServerSocket server = new ServerSocket(0)
        int port = server.localPort
        server.close()
        port
    }
}