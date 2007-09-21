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

package org.springframework.security.vote;

import org.springframework.security.vote.LabeledData;

import java.io.Serializable;


/**
 * For label unit tests.
 *
 * @author Greg Turnquist
 * @version $Id$
 */
public class SampleBlockOfData implements Serializable, LabeledData {
    //~ Static fields/initializers =====================================================================================

    private static final long serialVersionUID = 1L;
    public static final String DATA_LABEL_BLUE = "blue";
    public static final String DATA_LABEL_ORANGE = "orange";
    public static final String DATA_LABEL_SHARED = "blue-orange";

    //~ Instance fields ================================================================================================

    private String dataType;
    private String id;

    //~ Methods ========================================================================================================

    public String getId() {
        return id;
    }

    public String getLabel() {
        return dataType;
    }

    public String getSomeData() {
        return dataType;
    }

    public void setId(String ticketNumber) {
        this.id = ticketNumber;
    }

    public void setSomeData(String trafficType) {
        this.dataType = trafficType;
    }

    public String toString() {
        return this.id + "/" + this.dataType;
    }
}
