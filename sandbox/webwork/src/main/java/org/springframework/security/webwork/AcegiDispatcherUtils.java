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

import java.util.Map;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.acegisecurity.ui.ExceptionTranslationFilter;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.opensymphony.webwork.ServletActionContext;
import com.opensymphony.webwork.dispatcher.DispatcherUtils;
import com.opensymphony.webwork.dispatcher.mapper.ActionMapping;
import com.opensymphony.xwork.ActionContext;
import com.opensymphony.xwork.ActionProxy;
import com.opensymphony.xwork.ActionProxyFactory;
import com.opensymphony.xwork.Result;
import com.opensymphony.xwork.config.ConfigurationException;
import com.opensymphony.xwork.util.OgnlValueStack;
import com.opensymphony.xwork.util.XWorkContinuationConfig;

/**
 * <p>
 * WebWork {@link DispatcherUtils} that ignores Acegi exceptions so they can be processed by
 * {@link ExceptionTranslationFilter}.
 * </p>
 * 
 * <p>
 * This is meant to be fixed inside WebWork, see <a href="http://jira.opensymphony.com/browse/WW-291">WW-291</a>. Known
 * broken versions are 2.2.3 and 2.2.4.
 * </p>
 * 
 * @author <a href="mailto:carlos@apache.org">Carlos Sanchez</a>
 * @version $Id$
 */
public class AcegiDispatcherUtils extends DispatcherUtils {

    private static final Log LOG = LogFactory.getLog(AcegiDispatcherUtils.class);

    protected AcegiDispatcherUtils(ServletContext servletContext) {
        super(servletContext);
    }

    /**
     * <p>
     * Loads the action and executes it. This method first creates the action context from the given parameters then
     * loads an <tt>ActionProxy</tt> from the given action name and namespace. After that, the action is executed and
     * output channels throught the response object. Actions not found are sent back to the user via the
     * {@link DispatcherUtils#sendError} method, using the 404 return code. All other errors are reported by throwing a
     * ServletException.
     * </p>
     * 
     * <p>
     * Difference between this and WebWork prvided class is that any unhandled exception will be thrown instead of
     * processed inside WebWork.
     * </p>
     * 
     * @param request the HttpServletRequest object
     * @param response the HttpServletResponse object
     * @param mapping the action mapping object
     * @throws ServletException when an unknown error occurs (not a 404, but typically something that would end up as a
     * 5xx by the servlet container)
     */
    public void serviceAction(HttpServletRequest request, HttpServletResponse response, ServletContext context,
            ActionMapping mapping) throws ServletException {
        Map extraContext = createContextMap(request, response, mapping, context);

        // If there was a previous value stack, then create a new copy and pass it in to be used by the new Action
        OgnlValueStack stack = (OgnlValueStack) request.getAttribute(ServletActionContext.WEBWORK_VALUESTACK_KEY);
        if (stack != null) {
            extraContext.put(ActionContext.VALUE_STACK, new OgnlValueStack(stack));
        }

        try {
            String namespace = mapping.getNamespace();
            String name = mapping.getName();
            String method = mapping.getMethod();

            String id = request.getParameter(XWorkContinuationConfig.CONTINUE_PARAM);
            if (id != null) {
                // remove the continue key from the params - we don't want to bother setting
                // on the value stack since we know it won't work. Besides, this breaks devMode!
                Map params = (Map) extraContext.get(ActionContext.PARAMETERS);
                params.remove(XWorkContinuationConfig.CONTINUE_PARAM);

                // and now put the key in the context to be picked up later by XWork
                extraContext.put(XWorkContinuationConfig.CONTINUE_KEY, id);
            }

            ActionProxy proxy = ActionProxyFactory.getFactory().createActionProxy(namespace, name, extraContext, true,
                    false);
            proxy.setMethod(method);
            request.setAttribute(ServletActionContext.WEBWORK_VALUESTACK_KEY, proxy.getInvocation().getStack());

            // if the ActionMapping says to go straight to a result, do it!
            if (mapping.getResult() != null) {
                Result result = mapping.getResult();
                result.execute(proxy.getInvocation());
            } else {
                proxy.execute();
            }

            // If there was a previous value stack then set it back onto the request
            if (stack != null) {
                request.setAttribute(ServletActionContext.WEBWORK_VALUESTACK_KEY, stack);
            }
        } catch (ConfigurationException e) {
            LOG.error("Could not find action", e);
            sendError(request, response, context, HttpServletResponse.SC_NOT_FOUND, e);
        } catch (Exception e) {
            throw new ServletException(e);
        }
    }

}
