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

/**
 * A <i>value object</i>, which means a persistable business object  that does
 * not have its own persistence identity.
 * 
 * <p>
 * Every value object belongs to a single {@link
 * org.acegisecurity.domain.impl.AbstractPersistableEntity}. This is
 * necessary so that the value object has some sort of persistence
 * relationship/ownership.
 * </p>
 * 
 * <P>
 * In addition, a value object cannot be referenced from more than one
 * <code>PersistableEntity</code>. Use a <code>PersistableEntity</code>
 * instead of a  <code>PersistableValue</code> if this is a design constraint.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public abstract class PersistableValue extends BusinessObject {}
