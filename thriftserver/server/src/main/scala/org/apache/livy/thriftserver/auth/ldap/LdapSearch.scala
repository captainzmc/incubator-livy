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

import javax.naming.NamingException
import javax.naming.directory.DirContext

import org.apache.livy.{LivyConf, Logging}
/**
  * Implements search for LDAP.
  */
class LdapSearch (val conf: LivyConf, val ctx: DirContext) extends DirSearch with Logging {
  final private var baseDn: String = null
  baseDn = conf.get(LivyConf.THRIFT_LDAP_AUTHENTICATION_BASEDN)

  /**
    * Closes this search object and releases any system resources associated
    * with it. If the search object is already closed then invoking this
    * method has no effect.
    */
  def close(): Unit = {
    try
      ctx.close()
    catch {
      case e: NamingException =>
        warn("Exception when closing LDAP context:", e)
    }
  }

  @throws[NamingException]
  def findUserDn(user: String): String = {
    // TODO Finds user's distinguished name.
    null
  }

  @throws[NamingException]
  def findGroupDn(group: String): String = {
    // TODO Finds group's distinguished name.
    null
  }

  @throws[NamingException]
  def isUserMemberOfGroup(user: String, groupDn: String): Boolean = {
    // TODO Verifies that specified user is a member of specified group.
    false
  }

  @throws[NamingException]
  def findGroupsForUser(userDn: String): List[String] = {
    // TODO Finds groups that contain the specified user.
    null
  }

  @throws[NamingException]
  def executeCustomQuery(query: String): List[String] = {
    // TODO Executes an arbitrary query.
    null
  }

}
