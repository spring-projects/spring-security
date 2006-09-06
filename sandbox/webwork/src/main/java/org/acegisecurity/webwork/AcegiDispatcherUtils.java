/* Copyright 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.acegisecurity.webwork;

import java.io.IOException;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.acegisecurity.AccessDeniedException;
import org.acegisecurity.AcegiSecurityException;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.ui.ExceptionTranslationFilter;

import com.opensymphony.webwork.dispatcher.DispatcherUtils;

/**
 * WebWork {@link DispatcherUtils} that ignores Acegi exceptions so they can be processed by
 * {@link ExceptionTranslationFilter}
 * 
 * @author <a href="mailto:carlos@apache.org">Carlos Sanchez</a>
 * @version $Id$
 */
public class AcegiDispatcherUtils extends DispatcherUtils {

    protected AcegiDispatcherUtils(ServletContext servletContext) {
        super(servletContext);
    }

    /**
     * Sends an HTTP error response code on any exception that it's no an Acegi {@link AuthenticationException} or
     * {@link AccessDeniedException}
     * 
     * @param request the HttpServletRequest object.
     * @param response the HttpServletResponse object.
     * @param code the HttpServletResponse error code (see {@link javax.servlet.http.HttpServletResponse} for possible
     * error codes).
     * @param e the Exception that is reported.
     */
    public void sendError(HttpServletRequest request, HttpServletResponse response, ServletContext ctx, int code,
            Exception e) {
        if (devMode) {
            super.sendError(request, response, ctx, code, e);
        } else {
            try {
                // send a http error response to use the servlet defined error handler
                // make the exception availible to the web.xml defined error page
                request.setAttribute("javax.servlet.error.exception", e);

                // for compatibility
                request.setAttribute("javax.servlet.jsp.jspException", e);

                // do not send the error response if it's an acegi exception
                if (!isAcegiSecurityException(e)) {
                    response.sendError(code, e.getMessage());
                }
            } catch (IOException e1) {
                // we're already sending an error, not much else we can do if more stuff breaks
            }
        }
    }

    /**
     * Check if an object is an {@link AcegiSecurityException}.
     * 
     * @param o any object or <code>null</code>
     * @return true if the object passed is an {@link AuthenticationException} or {@link AccessDeniedException}
     */
    private boolean isAcegiSecurityException(Object o) {
        return ((o != null) && ((o instanceof AuthenticationException || o instanceof AccessDeniedException)));
    }

}
