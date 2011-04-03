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
package org.springframework.security.cas.web.authentication;

import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.cas.ServiceProperties;

/**
 * The {@code AuthenticationDetailsSource} that is set on the
 * {@code CasAuthenticationFilter} should return a value that implements
 * {@code ServiceAuthenticationDetails} if the application needs to authenticate
 * dynamic service urls. The
 * {@code ServiceAuthenticationDetailsSource#buildDetails(HttpServletRequest)}
 * creates a default {@code ServiceAuthenticationDetails}.
 *
 * @author Rob Winch
 */
public class ServiceAuthenticationDetailsSource implements AuthenticationDetailsSource<HttpServletRequest,
        ServiceAuthenticationDetails> {
    //~ Instance fields ================================================================================================

    private final Pattern artifactPattern;

    //~ Constructors ===================================================================================================

    /**
     * Creates an implementation that uses the default CAS artifactParameterName.
     */
    public ServiceAuthenticationDetailsSource() {
        this(ServiceProperties.DEFAULT_CAS_ARTIFACT_PARAMETER);
    }

    /**
     * Creates an implementation that uses the specified artifactParameterName
     *
     * @param artifactParameterName
     *            the artifactParameterName that is removed from the current
     *            URL. The result becomes the service url. Cannot be null and
     *            cannot be an empty String.
     */
    public ServiceAuthenticationDetailsSource(final String artifactParameterName) {
        this.artifactPattern = DefaultServiceAuthenticationDetails.createArtifactPattern(artifactParameterName);
    }

    //~ Methods ========================================================================================================

    /**
     * @param context the {@code HttpServletRequest} object.
     * @return the {@code ServiceAuthenticationDetails} containing information about the current request
     */
    public ServiceAuthenticationDetails buildDetails(HttpServletRequest context) {
        return new DefaultServiceAuthenticationDetails(context,artifactPattern);
    }
}