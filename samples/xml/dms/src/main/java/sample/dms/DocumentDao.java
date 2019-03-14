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
public interface DocumentDao {
	/**
	 * Creates an entry in the database for the element.
	 *
	 * @param element an unsaved element (the "id" will be updated after method is
	 * invoked)
	 */
	public void create(AbstractElement element);

	/**
	 * Removes a file from the database for the specified element.
	 *
	 * @param file the file to remove (cannot be null)
	 */
	public void delete(File file);

	/**
	 * Modifies a file in the database.
	 *
	 * @param file the file to update (cannot be null)
	 */
	public void update(File file);

	/**
	 * Locates elements in the database which appear under the presented directory
	 *
	 * @param directory the directory (cannot be null - use
	 * {@link Directory#ROOT_DIRECTORY} for root)
	 * @return zero or more elements in the directory (an empty array may be returned -
	 * never null)
	 */
	public AbstractElement[] findElements(Directory directory);
}
