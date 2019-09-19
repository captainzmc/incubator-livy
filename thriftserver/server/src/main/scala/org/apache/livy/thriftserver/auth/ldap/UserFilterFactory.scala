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


import java.util.{Collection, HashSet, List}

import javax.security.sasl.AuthenticationException

import org.apache.hadoop.util.StringUtils
import org.apache.livy.{LivyConf, Logging}


/**
  * A factory for a {@link Filter} based on a list of allowed users.
  * <br>
  * The produced filter object filters out all users that are not on the provided in
  * Livy configuration list.
  *
  * @see LivyConf.THRIFT_LDAP_AUTHENTICATION_USERFILTER
  */
object UserFilterFactory extends Logging{

  final private class UserFilter(val userFilter: Collection[String]) extends Filter {

    private var userFilterSet = new HashSet[String]
    for (userFilterItem:String <- userFilter) {
      userFilterSet.add(userFilterItem.toLowerCase)
    }

    @throws[AuthenticationException]
    def apply(ldap: DirSearch, user: String): Unit = {
      info("Authenticating user '{}' using user filter", user)
      val userName = LdapUtils.extractUserName(user).toLowerCase
      if (!userFilterSet.contains(userName)) {
        info("Authentication failed based on user membership")
        throw new AuthenticationException("Authentication failed: " + "User not a member of specified list")
      }
    }
  }

}

class UserFilterFactory extends FilterFactory {

  def getInstance(conf: LivyConf): Filter = {
    val userFilter:Collection[String] =
      StringUtils.getStringCollection(conf.get(LivyConf.THRIFT_LDAP_AUTHENTICATION_USERFILTER))
    if (userFilter.isEmpty) {
      null
    } else {
      new UserFilterFactory.UserFilter(userFilter)
    }

  }
}
