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

import java.util.{Collections, List, Collection, ArrayList}

import javax.management.Query
import javax.naming.NamingEnumeration
import javax.naming.NamingException
import javax.naming.directory.DirContext
import javax.naming.directory.SearchResult

import scala.collection.JavaConversions._

import org.apache.livy.{LivyConf, Logging}
/**
  * Implements search for LDAP.
  */
class LdapSearch (val conf: LivyConf, val ctx: DirContext) extends DirSearch with Logging {
  final private var baseDn: String = null
//  final private var groupBases: List[String] = null
//  final private var userBases: List[String] = null
//  final private var userPatterns: List[String] = null
//  final private var queries: QueryFactory = null
  baseDn = conf.get(LivyConf.THRIFT_LDAP_AUTHENTICATION_BASEDN)
//  userPatterns = LdapUtils.parseDnPatterns(conf, HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_USERDNPATTERN)
//  groupBases = LdapUtils.patternsToBaseDns(LdapUtils.parseDnPatterns(conf, HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_GROUPDNPATTERN))
//  userBases = LdapUtils.patternsToBaseDns(userPatterns)
//  queries = new Nothing(conf)

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

  /**
    * {@inheritDoc }
    */
  @throws[NamingException]
  def findUserDn(user: String): String = {
    var allLdapNames: List[String] = null
    if (LdapUtils.isDn(user)) {
      val userBaseDn = LdapUtils.extractBaseDn(user)
      val userRdn = LdapUtils.extractFirstRdn(user)
      allLdapNames = execute(Collections.singletonList(userBaseDn), queries.findUserDnByRdn(userRdn)).getAllLdapNames
    }
    else {
      allLdapNames = findDnByPattern(userPatterns, user)
      if (allLdapNames.isEmpty) allLdapNames = execute(userBases, queries.findUserDnByName(user)).getAllLdapNames
    }
    if (allLdapNames.size == 1) allLdapNames.get(0)
    else {
      info("Expected exactly one user result for the user: {}, but got {}. Returning null", user, allLdapNames.size)
      debug("Matched users: {}", allLdapNames)
      null
    }
  }

  @throws[NamingException]
  private def findDnByPattern(patterns: util.List[String], name: String): util.List[String] = {

    for (pattern <- patterns) {
      val baseDnFromPattern = LdapUtils.extractBaseDn(pattern)
      val rdn = LdapUtils.extractFirstRdn(pattern).replaceAll("%s", name)
      val list = execute(Collections.singletonList(baseDnFromPattern), queries.findDnByPattern(rdn)).getAllLdapNames
      if (!list.isEmpty) return list
    }
    Collections.emptyList
  }

  @throws[NamingException]
  def findGroupDn(group: String): String = execute(groupBases, queries.findGroupDnById(group)).getSingleLdapName

  @throws[NamingException]
  def isUserMemberOfGroup(user: String, groupDn: String): Boolean = {
    val userId = LdapUtils.extractUserName(user)
    execute(userBases, queries.isUserMemberOfGroup(userId, groupDn)).hasSingleResult
  }

  @throws[NamingException]
  def findGroupsForUser(userDn: String): util.List[String] = {
    val userName = LdapUtils.extractUserName(userDn)
    execute(groupBases, queries.findGroupsForUser(userName, userDn)).getAllLdapNames
  }

//  @throws[NamingException]
//  def executeCustomQuery(query: String): util.List[String] = execute(Collections.singletonList(baseDn), queries.customQuery(query)).getAllLdapNamesAndAttributes
//
//  private def execute(baseDns: Collection[String], query: Query) = {
//    val searchResults = new ArrayList[NamingEnumeration[SearchResult]]
//    debug("Executing a query: '{}' with base DNs {}.", query.getFilter, baseDns)
//    import scala.collection.JavaConversions._
//    for (aBaseDn <- baseDns) {
//      try {
//        val searchResult = ctx.search(aBaseDn, query.getFilter, query.getControls)
//        if (searchResult != null) searchResults.add(searchResult)
//      } catch {
//        case ex: NamingException =>
//          LdapSearch.LOG.debug("Exception happened for query '" + query.getFilter + "' with base DN '" + aBaseDn + "'", ex)
//      }
//    }
//    new Nothing(searchResults)
//  }
}
