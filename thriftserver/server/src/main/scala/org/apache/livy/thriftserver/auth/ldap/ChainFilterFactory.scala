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

import java.util.{Collections, List, ArrayList}
import javax.security.sasl.AuthenticationException


import scala.collection.JavaConversions._

import org.apache.livy.LivyConf

/**
  * A factory that produces a Filter that is implemented as a chain of other filters.
  * The chain of filters are created as a result of
  * getInstance(org.apache.livy.LivyConf)
  */

object ChainFilterFactory {

  final private class ChainFilter(val chainedFilters: List[Filter]) extends Filter {
    @throws[AuthenticationException]
    def apply(client: DirSearch, user: String): Unit = {
      for (filter <- chainedFilters) {
        filter.apply(client, user)
      }
    }
  }
}

class ChainFilterFactory(val factories: List[FilterFactory]) extends FilterFactory {

  private var chainedFactories = Collections.unmodifiableList(factories)

  def getInstance(conf: LivyConf): Filter = {
    var filters =  List[Filter]()

    for (factory <- chainedFactories) {
      val filter = factory.getInstance(conf)
      if (filter != null) filters.add(filter)
    }
    if (filters.isEmpty) {
      null
    } else {
      new ChainFilterFactory.ChainFilter(filters)
    }
  }
}