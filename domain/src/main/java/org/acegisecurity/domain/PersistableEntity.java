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

package net.sf.acegisecurity.domain;

import java.io.Serializable;


/**
 * An interface that indicates an object is a <i>persistable entity</i>.
 * 
 * <p>
 * A persistable entity is any object that is capable of being persisted,
 * typically via a {@link net.sf.acegisecurity.domain.dao.Dao} implementation.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface PersistableEntity {
    //~ Methods ================================================================

    /**
     * Provides a common getter for the persistence layer to obtain an
     * identity, irrespective of the actual type of identity used.
     * 
     * <p>
     * Typically a subclass will delegate to a <code>public
     * SomePrimitiveWrapper getId()</code> method. The necessity for the
     * <code>getInternalId()</code> abstract method is solely  because the
     * persistence layer needs a way of obtaining the identity irrespective of
     * the actual identity implementation choice.
     * </p>
     * 
     * <p>
     * Returning <code>null</code> from this method will indicate the object
     * has never been saved. This will likely be relied on by some
     * <code>Dao</code> implementations.
     * </p>
     *
     * @return the persistence identity of this instance
     */
    abstract Serializable getInternalId();
}
