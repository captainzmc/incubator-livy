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
package org.apache.livy.thriftserver.auth

import java.util.{Collections}

import javax.security.sasl.AuthenticationException

import scala.collection.JavaConverters._

import com.google.common.annotations.VisibleForTesting
import com.google.common.collect.ImmutableList

import org.apache.commons.lang.StringUtils

import org.apache.hive.service.auth.PasswdAuthenticationProvider

import org.apache.livy.thriftserver.auth.ldap.CustomQueryFilterFactory
import org.apache.livy.thriftserver.auth.ldap.LdapSearchFactory
import org.apache.livy.thriftserver.auth.ldap.Filter
import org.apache.livy.thriftserver.auth.ldap.DirSearch
import org.apache.livy.thriftserver.auth.ldap.DirSearchFactory
import org.apache.livy.thriftserver.auth.ldap.UserFilterFactory
import org.apache.livy.thriftserver.auth.ldap.LdapUtils
import org.apache.livy.thriftserver.auth.ldap.ChainFilterFactory
import org.apache.livy.thriftserver.auth.ldap.FilterFactory
import org.apache.livy.{LivyConf, Logging}


object LdapAuthenticationProviderImpl {

  // Initialize the Chain FilterFactory List. Now GroupFilter is not supported.
  // If needed, GroupFilterFactory can be added in this list.
  var chainFactories: List[FilterFactory] = List[FilterFactory](new UserFilterFactory)

  // Initialize the FilterFactory List
  var factories: List[FilterFactory] = List[FilterFactory](
    new ChainFilterFactory(chainFactories.asJava), new CustomQueryFilterFactory)

  private val filterFactories = Collections.unmodifiableList[FilterFactory](factories.asJava)

  private def resolveFilter(conf: LivyConf): Filter = {
    var filter: Filter = null
    for (filterProvider: FilterFactory <- filterFactories) {
      if (filter != filterProvider.getInstance(conf)) {
        filter = filterProvider.getInstance(conf)
      }
    }
    filter
  }
}

class LdapAuthenticationProviderImpl(val conf: LivyConf) extends PasswdAuthenticationProvider with Logging{
  final private val filter: Filter = LdapAuthenticationProviderImpl.resolveFilter(conf)
  final private val searchFactory: DirSearchFactory = new LdapSearchFactory()

  @throws(classOf[AuthenticationException])
  def Authenticate(user: String, password: String): Unit = {
    var search: DirSearch = null
    search = createDirSearch(user, password)
    applyFilter(search, user)
  }

  @throws(classOf[AuthenticationException])
  private def createDirSearch(user: String, password: String): DirSearch = {
    if (StringUtils.isBlank(user) || StringUtils.isEmpty(user)) {
      throw new AuthenticationException("Error validating LDAP:" +
        " a null or blank user name has been provided")
    }
    if (StringUtils.isBlank(password) || StringUtils.isEmpty(password)) {
      throw new AuthenticationException("Error validating LDAP:" +
        " a null or blank password has been provided")
    }
    val principal = LdapUtils.createCandidatePrincipal(conf, user)
    try {
      searchFactory.getInstance(conf, principal, password)
    } catch {
      case e: AuthenticationException =>
        throw new AuthenticationException(s"Error validating " +
          s"LDAP user: $user, password: $password", e)
    }

  }

  @throws(classOf[AuthenticationException])
  private def applyFilter(client: DirSearch, user: String): Unit = {
    if (filter != null) {
      if (LdapUtils.hasDomain(user)) {
        filter.apply(client, LdapUtils.extractUserName(user))
      }
      else {
        filter.apply(client, user)
      }
    }
  }
}
