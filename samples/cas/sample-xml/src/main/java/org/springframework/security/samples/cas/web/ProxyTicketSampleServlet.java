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
package org.springframework.security.samples.cas.web;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URLEncoder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jasig.cas.client.util.CommonUtils;
import org.springframework.security.cas.authentication.CasAuthenticationToken;

/**
 * <p>
 * {@link ProxyTicketSampleServlet} demonstrates how to obtain a proxy ticket
 * and then use it to make a remote call. To learn how proxy tickets work, see
 * the <a href="https://wiki.jasig.org/display/CAS/Proxy+CAS+Walkthrough">Proxy
 * CAS Walkthrough</a>
 * </p>
 *
 * @author Rob Winch
 */
public final class ProxyTicketSampleServlet extends HttpServlet {
    /**
     * This is the URL that will be called and authenticate a proxy ticket.
     */
    private String targetUrl;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // NOTE: The CasAuthenticationToken can also be obtained using SecurityContextHolder.getContext().getAuthentication()
        final CasAuthenticationToken token = (CasAuthenticationToken) request.getUserPrincipal();
        // proxyTicket could be reused to make calls to to the CAS service even if the target url differs
        final String proxyTicket = token.getAssertion().getPrincipal().getProxyTicketFor(targetUrl);

        // Make a remote call to ourself. This is a bit silly, but it works well to demonstrate how to use proxy tickets.
        final String serviceUrl = targetUrl+"?ticket="+URLEncoder.encode(proxyTicket, "UTF-8");
        String proxyResponse = CommonUtils.getResponseFromServer(serviceUrl, "UTF-8");

        // modify the response and write it out to inform the user that it was obtained using a proxy ticket.
        proxyResponse = proxyResponse.replaceFirst("Secure Page", "Secure Page using a Proxy Ticket");
        proxyResponse = proxyResponse.replaceFirst("<p>",
                "<p>This page is rendered by "+getClass().getSimpleName()+" by making a remote call to the Secure Page using a proxy ticket ("+proxyTicket+") and inserts this message. ");
        final PrintWriter writer = response.getWriter();
        writer.write(proxyResponse);
    }

    /**
     * Initialize the target URL. It allows for the host to change based upon
     * the "cas.service.host" system property. If the property is not set, the
     * default is "localhost:8443".
     */
    @Override
    public void init() throws ServletException {
        super.init();
        String casServiceHost = System.getProperty("cas.service.host", "localhost:8443");
        targetUrl = "https://"+casServiceHost+"/cas-sample/secure/";
    }

    private static final long serialVersionUID = -7720161771819727775L;
}
