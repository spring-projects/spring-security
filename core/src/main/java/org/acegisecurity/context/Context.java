/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.context;

import java.io.Serializable;


/**
 * Holds objects that are needed on every request.
 * 
 * <P>
 * A <code>Context</code> will be sent between application tiers  via a  {@link
 * ContextHolder}.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface Context extends Serializable {
    //~ Methods ================================================================

    /**
     * Check the <code>Context</code> is properly configured.
     * 
     * <P>
     * This allows implementations to confirm they are valid, as this method is
     * automatically called by the {@link ContextInterceptor}.
     * </p>
     *
     * @throws ContextInvalidException if the <code>Context</code> is invalid.
     */
    public void validate() throws ContextInvalidException;
}
