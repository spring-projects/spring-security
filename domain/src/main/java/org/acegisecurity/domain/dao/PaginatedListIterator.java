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

package net.sf.acegisecurity.domain.dao;

import java.util.Iterator;
import java.util.NoSuchElementException;


/**
 * An iterator of the <code>PaginatedList</code>.
 *
 * @author Carlos Sanchez
 * @version $Id$
 */
public class PaginatedListIterator implements Iterator {
    //~ Instance fields ========================================================

    private Iterator iterator;
    private PaginatedList list;
    private int i = 0;

    //~ Constructors ===========================================================

    /**
     * DOCUMENT ME!
     *
     * @param list
     */
    public PaginatedListIterator(PaginatedList list) {
        this.list = list;
    }

    //~ Methods ================================================================

    /**
     * @see java.util.Iterator#hasNext()
     */
    public boolean hasNext() {
        return i < list.size();
    }

    /**
     * This method follows the rules of Iterator.next() except that it returns
     * null when requesting an element that it's not in the current page.
     *
     * @see java.util.Iterator#next()
     */
    public Object next() {
        if (i == list.getFirstElement()) {
            iterator = list.getList().iterator();
        }

        if ((i >= list.getFirstElement())
            && (i < (list.getFirstElement() + list.getMaxElements()))) {
            i++;

            return iterator.next();
        }

        if (hasNext()) {
            i++;

            return null;
        } else {
            throw new NoSuchElementException();
        }
    }

    /**
     * Unsupported operation
     *
     * @throws UnsupportedOperationException
     *
     * @see java.util.Iterator#remove()
     */
    public void remove() {
        throw new UnsupportedOperationException();
    }
}
