/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.livy.thriftserver.auth.ldap

import org.apache.livy.LivyConf

/**
  * A factory for a Filter based on a custom query.
  * The produced filter object filters out all users that are not found in the search result
  * of the query provided in Livy configuration.
  *
  */
class CustomQueryFilterFactory extends FilterFactory {

  def getInstance(conf: LivyConf): Filter = {

    // TODO We don't support custom query at the moment now. If it needed can be added here.
    // The CustomQueryFilter should have a higher priority than the other filters.
    // Set the CustomQueryFilter to invalidate the other filters.
    null
  }
}
