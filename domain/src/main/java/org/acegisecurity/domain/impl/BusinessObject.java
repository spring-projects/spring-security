/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

package org.acegisecurity.domain.impl;

import org.acegisecurity.domain.util.ReflectionToStringBuilder;

import org.apache.commons.beanutils.BeanUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.Serializable;


/**
 * A business domain object.
 * 
 * <p>
 * Only minimal convenience methods are provided by
 * <code>BusinessObject</code>. Whilst many other methods could easily be
 * offered (and overridden on an as-required basis) it is felt the default
 * behaviour of {@link java.lang.Object} is widely understood and an
 * appropriate default.
 * </p>
 *
 * @author Carlos Sanchez
 * @author Ben Alex
 * @author Matthew Porter
 * @version $Id$
 */
public abstract class BusinessObject implements Serializable, Cloneable {
    //~ Instance fields ========================================================

    protected final transient Log logger = LogFactory.getLog(getClass());

    //~ Methods ================================================================

    /**
     * Swallow cloning.
     * 
     * <p>
     * This method delegates to BeanUtils.cloneBean().
     * </p>
     *
     * @return a clone of the current instance
     *
     * @throws IllegalStateException if there are any problems with swallow
     *         cloning
     *
     * @see java.lang.Object#clone()
     * @see BeanUtils#cloneBean(Object)
     */
    public Object clone() throws CloneNotSupportedException {
        try {
            return BeanUtils.cloneBean(this);
        } catch (Exception e) {
            logger.error(e);
            throw new CloneNotSupportedException(e.getMessage());
        }
    }

    /**
     * Delegates to {@link CollectionIgnoringReflectionToStringBuilder}.
     *
     * @see java.lang.Object#toString()
     */
    public String toString() {
        return new ReflectionToStringBuilder(this).toString();
    }
}
