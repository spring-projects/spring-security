/*
 * Licensed to Apereo under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Apereo licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.springframework.security.cas.web;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.jasig.cas.client.Protocol;
import org.jasig.cas.client.proxy.ProxyGrantingTicketStorage;
import org.jasig.cas.client.util.URIBuilder;

import org.springframework.util.StringUtils;

final class CommonUtils {

	private static final String PARAM_PROXY_GRANTING_TICKET_IOU = "pgtIou";

	/**
	 * Constant representing the ProxyGrantingTicket Request Parameter.
	 */
	private static final String PARAM_PROXY_GRANTING_TICKET = "pgtId";

	private static final String SERVICE_PARAMETER_NAMES;

	private CommonUtils() {

	}

	static {
		final Set<String> serviceParameterSet = new HashSet<String>(4);
		for (final Protocol protocol : Protocol.values()) {
			serviceParameterSet.add(protocol.getServiceParameterName());
		}
		SERVICE_PARAMETER_NAMES = serviceParameterSet.toString().replaceAll("\\[|\\]", "").replaceAll("\\s", "");
	}

	static String constructServiceUrl(final HttpServletRequest request, final HttpServletResponse response,
			final String service, final String serverNames, final String artifactParameterName, final boolean encode) {
		if (StringUtils.hasText(service)) {
			return encode ? response.encodeURL(service) : service;
		}

		final String serverName = findMatchingServerName(request, serverNames);
		final URIBuilder originalRequestUrl = new URIBuilder(request.getRequestURL().toString(), encode);
		originalRequestUrl.setParameters(request.getQueryString());

		final URIBuilder builder;
		if (!serverName.startsWith("https://") && !serverName.startsWith("http://")) {
			final String scheme = request.isSecure() ? "https://" : "http://";
			builder = new URIBuilder(scheme + serverName, encode);
		}
		else {
			builder = new URIBuilder(serverName, encode);
		}

		if (builder.getPort() == -1 && !requestIsOnStandardPort(request)) {
			builder.setPort(request.getServerPort());
		}

		builder.setEncodedPath(builder.getEncodedPath() + request.getRequestURI());

		final List<String> serviceParameterNames = Arrays.asList(SERVICE_PARAMETER_NAMES.split(","));
		if (!serviceParameterNames.isEmpty() && !originalRequestUrl.getQueryParams().isEmpty()) {
			for (final URIBuilder.BasicNameValuePair pair : originalRequestUrl.getQueryParams()) {
				final String name = pair.getName();
				if (!name.equals(artifactParameterName) && !serviceParameterNames.contains(name)) {
					if (name.contains("&") || name.contains("=")) {
						final URIBuilder encodedParamBuilder = new URIBuilder();
						encodedParamBuilder.setParameters(name);
						for (final URIBuilder.BasicNameValuePair pair2 : encodedParamBuilder.getQueryParams()) {
							final String name2 = pair2.getName();
							if (!name2.equals(artifactParameterName) && !serviceParameterNames.contains(name2)) {
								builder.addParameter(name2, pair2.getValue());
							}
						}
					}
					else {
						builder.addParameter(name, pair.getValue());
					}
				}
			}
		}

		final String result = builder.toString();
		final String returnValue = encode ? response.encodeURL(result) : result;
		return returnValue;
	}

	static String constructRedirectUrl(final String casServerLoginUrl, final String serviceParameterName,
			final String serviceUrl, final boolean renew, final boolean gateway, final String method) {
		return casServerLoginUrl + (casServerLoginUrl.contains("?") ? "&" : "?") + serviceParameterName + "="
				+ urlEncode(serviceUrl) + (renew ? "&renew=true" : "") + (gateway ? "&gateway=true" : "")
				+ ((method != null) ? "&method=" + method : "");
	}

	static String urlEncode(final String value) {
		return URLEncoder.encode(value, StandardCharsets.UTF_8);
	}

	static void readAndRespondToProxyReceptorRequest(final HttpServletRequest request,
			final HttpServletResponse response, final ProxyGrantingTicketStorage proxyGrantingTicketStorage)
			throws IOException {
		final String proxyGrantingTicketIou = request.getParameter(PARAM_PROXY_GRANTING_TICKET_IOU);

		final String proxyGrantingTicket = request.getParameter(PARAM_PROXY_GRANTING_TICKET);

		if (org.jasig.cas.client.util.CommonUtils.isBlank(proxyGrantingTicket)
				|| org.jasig.cas.client.util.CommonUtils.isBlank(proxyGrantingTicketIou)) {
			response.getWriter().write("");
			return;
		}

		proxyGrantingTicketStorage.save(proxyGrantingTicketIou, proxyGrantingTicket);

		response.getWriter().write("<?xml version=\"1.0\"?>");
		response.getWriter().write("<casClient:proxySuccess xmlns:casClient=\"https://www.yale.edu/tp/casClient\" />");
	}

	private static String findMatchingServerName(final HttpServletRequest request, final String serverName) {
		final String[] serverNames = serverName.split(" ");

		if (serverNames.length == 0 || serverNames.length == 1) {
			return serverName;
		}

		final String host = request.getHeader("Host");
		final String xHost = request.getHeader("X-Forwarded-Host");

		final String comparisonHost;
		comparisonHost = (xHost != null) ? xHost : host;

		if (comparisonHost == null) {
			return serverName;
		}

		for (final String server : serverNames) {
			final String lowerCaseServer = server.toLowerCase();

			if (lowerCaseServer.contains(comparisonHost)) {
				return server;
			}
		}

		return serverNames[0];
	}

	private static boolean requestIsOnStandardPort(final HttpServletRequest request) {
		final int serverPort = request.getServerPort();
		return serverPort == 80 || serverPort == 443;
	}

}
