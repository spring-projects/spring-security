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

import javax.servlet.FilterConfig;
import javax.servlet.ServletException;

import org.acegisecurity.ui.ExceptionTranslationFilter;

import com.opensymphony.webwork.dispatcher.DispatcherUtils;

/**
 * <p>
 * {@link com.opensymphony.webwork.dispatcher.FilterDispatcher} that will setup WebWork to ignore Acegi exceptions so
 * they can be processed by {@link ExceptionTranslationFilter}
 * </p>
 * 
 * <p>
 * Set it up in your web.xml instead of WebWrok provided {@link com.opensymphony.webwork.dispatcher.FilterDispatcher}.
 * </p>
 * 
 * @author <a href="mailto:carlos@apache.org">Carlos Sanchez</a>
 * @version $Id$
 */
public class FilterDispatcher extends com.opensymphony.webwork.dispatcher.FilterDispatcher {

    public void init(FilterConfig filterConfig) throws ServletException {
        super.init(filterConfig);
        DispatcherUtils.setInstance(new AcegiDispatcherUtils(filterConfig.getServletContext()));
    }

}
