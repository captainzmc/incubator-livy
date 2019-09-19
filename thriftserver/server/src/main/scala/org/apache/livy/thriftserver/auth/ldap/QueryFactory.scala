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

import com.google.common.base.Strings
import javax.management.Query


/**
  * A factory for common types of directory service search queries.
  */
object QueryFactory {
  private val USER_OBJECT_CLASSES = Array("person", "user", "inetOrgPerson")
}

final class QueryFactory(val conf: HiveConf)

/**
  * Constructs the factory based on provided Hive configuration.
  *
  * @param conf Hive configuration
  */ {
  guidAttr = conf.getVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_GUIDKEY)
  groupClassAttr = conf.getVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_GROUPCLASS_KEY)
  groupMembershipAttr = conf.getVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_GROUPMEMBERSHIP_KEY)
  userMembershipAttr = conf.getVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_USERMEMBERSHIP_KEY)
  final private var guidAttr = null
  final private var groupClassAttr = null
  final private var groupMembershipAttr = null
  final private var userMembershipAttr = null

  /**
    * Returns a query for finding Group DN based on group unique ID.
    *
    * @param groupId group unique identifier
    * @return an instance of { @link Query}
    */
  def findGroupDnById(groupId: String): Query = Query.builder.filter("(&(objectClass=<groupClassAttr>)(<guidAttr>=<groupID>))").map("guidAttr", guidAttr).map("groupClassAttr", groupClassAttr).map("groupID", groupId).limit(2).build

  /**
    * Returns a query for finding user DN based on user RDN.
    *
    * @param userRdn user RDN
    * @return an instance of { @link Query}
    */
  def findUserDnByRdn(userRdn: String): Query = Query.builder.filter("(&(|<classes:{ class |(objectClass=<class>)}>)" + "(<userRdn>))").limit(2).map("classes", QueryFactory.USER_OBJECT_CLASSES).map("userRdn", userRdn).build

  /**
    * Returns a query for finding user DN based on DN pattern.
    * <br>
    * Name of this method was derived from the original implementation of LDAP authentication.
    * This method should be replaced by {@link QueryFactory#findUserDnByRdn(java.lang.String).
   *
   * @param rdn user RDN
   * @return an instance of {@link Query}
    */
  def findDnByPattern(rdn: String): Query = Query.builder.filter("(<rdn>)").map("rdn", rdn).limit(2).build

  /**
    * Returns a query for finding user DN based on user unique name.
    *
    * @param userName user unique name (uid or sAMAccountName)
    * @return an instance of { @link Query}
    */
  def findUserDnByName(userName: String): Query = {
    Query.builder.filter("(&(|<classes:{ class |(objectClass=<class>)}>)" + "(|(uid=<userName>)(sAMAccountName=<userName>)))").map("classes", QueryFactory.USER_OBJECT_CLASSES).map("userName", userName).limit(2).build
  }

  /**
    * Returns a query for finding groups to which the user belongs.
    *
    * @param userName username
    * @param userDn   user DN
    * @return an instance of { @link Query}
    */
  def findGroupsForUser(userName: String, userDn: String): Query = Query.builder.filter("(&(objectClass=<groupClassAttr>)(|(<groupMembershipAttr>=<userDn>)" + "(<groupMembershipAttr>=<userName>)))").map("groupClassAttr", groupClassAttr).map("groupMembershipAttr", groupMembershipAttr).map("userName", userName).map("userDn", userDn).build

  /**
    * Returns a query for checking whether specified user is a member of specified group.
    *
    * The query requires {@value HiveConf#HIVE_SERVER2_AUTHENTICATION_LDAP_USERMEMBERSHIPKEY_NAME}
    * Hive configuration property to be set.
    *
    * @param userId  user unique identifier
    * @param groupDn group DN
    * @return an instance of { @link Query}
    * @see HiveConf.ConfVars#HIVE_SERVER2_PLAIN_LDAP_USERMEMBERSHIP_KEY
    * @throws NullPointerException when
    *                              { @value HiveConf#HIVE_SERVER2_AUTHENTICATION_LDAP_USERMEMBERSHIPKEY_NAME} is not set.
    */
  def isUserMemberOfGroup(userId: String, groupDn: String): Query = {
    Preconditions.checkState(!Strings.isNullOrEmpty(userMembershipAttr), "hive.server2.authentication.ldap.userMembershipKey is not configured.")
    Query.builder.filter("(&(|<classes:{ class |(objectClass=<class>)}>)" + "(<userMembershipAttr>=<groupDn>)(<guidAttr>=<userId>))").map("classes", QueryFactory.USER_OBJECT_CLASSES).map("guidAttr", guidAttr).map("userMembershipAttr", userMembershipAttr).map("userId", userId).map("groupDn", groupDn).limit(2).build
  }

  /**
    * Returns a query object created for the custom filter.
    * <br>
    * This query is configured to return a group membership attribute as part of the search result.
    *
    * @param searchFilter custom search filter
    * @return an instance of { @link Query}
    */
  def customQuery(searchFilter: String): Query = {
    val builder = Query.builder
    builder.filter(searchFilter)
    if (!Strings.isNullOrEmpty(groupMembershipAttr)) builder.returnAttribute(groupMembershipAttr)
    builder.build
  }
}

