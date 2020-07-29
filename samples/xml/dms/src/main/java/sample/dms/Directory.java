/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package sample.dms;

/**
 *
 * @author Ben Alex
 *
 */
public class Directory extends AbstractElement {
	public static final Directory ROOT_DIRECTORY = new Directory();

	private Directory() {
	}

	public Directory(String name, Directory parent) {
		super(name, parent);
	}

	@Override
	public String toString() {
		return "Directory[fullName='" + getFullName() + "'; name='" + getName()
				+ "'; id='" + getId() + "'; parent='" + getParent() + "']";
	}

}
