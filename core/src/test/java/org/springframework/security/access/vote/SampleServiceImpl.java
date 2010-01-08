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
package org.springframework.security.access.vote;

import java.util.List;
import java.util.Vector;


/**
 * For label unit tests.
 *
 * @author Greg Turnquist
 */
public class SampleServiceImpl implements SampleService {
    //~ Methods ========================================================================================================

    public void doSomethingOnThis(SampleBlockOfData block1, SampleBlockOfData block2) {
    }

    public List<SampleBlockOfData> getTheSampleData() {
        List<SampleBlockOfData> dataList = new Vector<SampleBlockOfData>();
        SampleBlockOfData block;

        block = new SampleBlockOfData();
        block.setId("001");
        block.setSomeData(SampleBlockOfData.DATA_LABEL_BLUE);
        dataList.add(block);

        block = new SampleBlockOfData();
        block.setId("002");
        block.setSomeData(SampleBlockOfData.DATA_LABEL_ORANGE);
        dataList.add(block);

        block = new SampleBlockOfData();
        block.setId("003");
        block.setSomeData(SampleBlockOfData.DATA_LABEL_SHARED);
        dataList.add(block);

        return dataList;
    }
}
