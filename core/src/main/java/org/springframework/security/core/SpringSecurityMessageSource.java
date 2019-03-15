/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.core;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.context.support.ResourceBundleMessageSource;


/**
 * The default <code>MessageSource</code> used by Spring Security.
 * <p>All Spring Security classes requiring messge localization will by default use this class.
 * However, all such classes will also implement <code>MessageSourceAware</code> so that the application context can
 * inject an alternative message source. Therefore this class is only used when the deployment environment has not
 * specified an alternative message source.</p>
 *
 * @author Ben Alex
 */
public class SpringSecurityMessageSource extends ResourceBundleMessageSource {
    //~ Constructors ===================================================================================================

    public SpringSecurityMessageSource() {
        setBasename("org.springframework.security.messages");
    }

    //~ Methods ========================================================================================================

    public static MessageSourceAccessor getAccessor() {
        return new MessageSourceAccessor(new SpringSecurityMessageSource());
    }
}
