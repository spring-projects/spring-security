/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.acegisecurity.vote;

import java.lang.reflect.Method;


/**
 * This is a very useful implementation of the LabelParameterStrategy. Data objects which are meant to be labeled
 * should implement the LabeledData interface. This strategy will then castdown to that interface for either testing
 * or retrieval of the label.
 *
 * @author Greg Turnquist
 * @version $Id$
 */
public class InterfaceBasedLabelParameterStrategy implements LabelParameterStrategy {
    //~ Instance fields ================================================================================================

    private String noLabel = "";

    //~ Methods ========================================================================================================

    /**
     * Test if the argument is labeled, and if so, downcast to LabeledData and retrieve the domain object's
     * labeled value. Otherwise, return an empty string. NOTE: The default for no label is an empty string. If somehow
     * the user wants to make that a label itself, he or she must inject an alternate value to the noLabel property.
     *
     * @param method DOCUMENT ME!
     * @param arg DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getLabel(Method method, Object arg) {
        if (isLabeled(method, arg)) {
            return ((LabeledData) arg).getLabel();
        } else {
            return noLabel;
        }
    }

    public String getNoLabel() {
        return noLabel;
    }

    /**
     * Test if the argument implemented the LabeledData interface. NOTE: The invoking method has no bearing for
     * this strategy, only the argument itself.
     *
     * @param method DOCUMENT ME!
     * @param arg DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean isLabeled(Method method, Object arg) {
        return (arg instanceof LabeledData);
    }

    public void setNoLabel(String noLabel) {
        this.noLabel = noLabel;
    }
}
