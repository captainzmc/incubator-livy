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

import java.util
import java.util.{Collections, ArrayList}
import scala.collection.JavaConversions._

import org.apache.commons.lang.StringUtils
import org.apache.livy.{LivyConf, Logging}


/**
  * Static utility methods related to LDAP authentication module.
  */
object LdapUtils extends Logging{

  /**
    * Extracts a base DN from the provided distinguished name.
    * <br>
    * <b>Example:</b>
    * <br>
    * "ou=CORP,dc=mycompany,dc=com" is the base DN for "cn=user1,ou=CORP,dc=mycompany,dc=com"
    *
    * @param dn distinguished name
    * @return base DN
    */
  def extractBaseDn(dn: String): String = {
    val indexOfFirstDelimiter = dn.indexOf(",")
    if (indexOfFirstDelimiter > -1) {
      dn.substring(indexOfFirstDelimiter + 1)
    } else {
      null
    }
  }

  /**
    * Extracts the first Relative Distinguished Name (RDN).
    * <br>
    * <b>Example:</b>
    * <br>
    * For DN "cn=user1,ou=CORP,dc=mycompany,dc=com" this method will return "cn=user1"
    *
    * @param dn distinguished name
    * @return first RDN
    */
  def extractFirstRdn(dn: String): String = {
    dn.substring(0, dn.indexOf(","))
  }

  /**
    * Extracts username from user DN.
    * <br>
    * <b>Examples:</b>
    * <pre>
    * LdapUtils.extractUserName("UserName")                        = "UserName"
    * LdapUtils.extractUserName("UserName@mycorp.com")             = "UserName"
    * LdapUtils.extractUserName("cn=UserName,dc=mycompany,dc=com") = "UserName"
    * </pre>
    *
    * @param userDn
    * @return
    */
  def extractUserName(userDn: String): String = {
    if (!isDn(userDn) && !hasDomain(userDn)) return userDn
    val domainIdx = indexOfDomainMatch(userDn)
    if (domainIdx > 0) return userDn.substring(0, domainIdx)
    if (userDn.contains("=")) return userDn.substring(userDn.indexOf("=") + 1, userDn.indexOf(","))
    userDn
  }

  /**
    * Get the index separating the user name from domain name (the user's name up
    * to the first '/' or '@').
    *
    * @param userName full user name.
    * @return index of domain match or -1 if not found
    */
  def indexOfDomainMatch(userName: String): Int = {
    if (userName == null) return -1
    val idx = userName.indexOf('/')
    val idx2 = userName.indexOf('@')
    var endIdx = Math.min(idx, idx2) // Use the earlier match.
    // Unless at least one of '/' or '@' was not found, in
    // which case, user the latter match.
    if (endIdx == -1) endIdx = Math.max(idx, idx2)
    endIdx
  }

  /**
    * Gets value part of the first attribute in the provided RDN.
    * <br>
    * <b>Example:</b>
    * <br>
    * For RDN "cn=user1,ou=CORP" this method will return "user1"
    *
    * @param rdn Relative Distinguished Name
    * @return value part of the first attribute
    */
  def getShortName(rdn: String): String = {
    (rdn.split(","))(0).split("=")(1)
  }

  /**
    * Check for a domain part in the provided username.
    * <br>
    * <b>Example:</b>
    * <br>
    * <pre>
    * LdapUtils.hasDomain("user1@mycorp.com") = true
    * LdapUtils.hasDomain("user1")            = false
    * </pre>
    *
    * @param userName username
    * @return true if { @code userName} contains { @code @<domain>} part
    */
  def hasDomain(userName: String): Boolean = {
    indexOfDomainMatch(userName) > 0
  }

  /**
    * Detects DN names.
    * <br>
    * <b>Example:</b>
    * <br>
    * <pre>
    * LdapUtils.isDn("cn=UserName,dc=mycompany,dc=com") = true
    * LdapUtils.isDn("user1")                           = false
    * </pre>
    *
    * @param name name to be checked
    * @return true if the provided name is a distinguished name
    */
  def isDn(name: String): Boolean = {
    name.contains("=")
  }

//  /**
//    * Reads and parses DN patterns from Hive configuration.
//    * <br>
//    * If no patterns are provided in the configuration, then the base DN will be used.
//    *
//    * @param conf Hive configuration
//    * @param var  variable to be read
//    * @return a list of DN patterns
//    * @see HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_BASEDN
//    * @see HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_GUIDKEY
//    * @see HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_GROUPDNPATTERN
//    * @see HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_USERDNPATTERN
//    */
//  def parseDnPatterns(conf: LivyConf): List[String] = {
//    val patternsString = conf.getVar(`var`)
//    val result = new util.ArrayList[String]
//    if (StringUtils.isBlank(patternsString)) {
//      val defaultBaseDn = conf.getVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_BASEDN)
//      val guidAttr = conf.getVar(HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_GUIDKEY)
//      if (StringUtils.isNotBlank(defaultBaseDn)) result.add(guidAttr + "=%s," + defaultBaseDn)
//    }
//    else {
//      val patterns = patternsString.split(":")
//      for (pattern <- patterns) {
//        if (pattern.contains(",") && pattern.contains("=")) result.add(pattern)
//        else LOG.warn("Unexpected format for " + `var` + "..ignoring " + pattern)
//      }
//    }
//    result
//  }

  private def patternToBaseDn(pattern: String): String = {
    if (pattern.contains("=%s")) return pattern.split(",", 2)(1)
    pattern
  }

  /**
    * Converts a collection of Distinguished Name patterns to a collection of base DNs.
    *
    * @param patterns Distinguished Name patterns
    * @return a list of base DNs
    * @see HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_GROUPDNPATTERN
    * @see HiveConf.ConfVars.HIVE_SERVER2_PLAIN_LDAP_USERDNPATTERN
    */
  def patternsToBaseDns(patterns: util.Collection[String]): List[String] = {
    val result = new util.ArrayList[String]
    for (pattern <- patterns) {
      result.add(patternToBaseDn(pattern))
    }
    result
  }

  /**
    * Creates a principal to be used for user authentication.
    *
    * @param conf Livy configuration
    * @param user username
    * @return a list of user's principal
    */
  def createCandidatePrincipal(conf: LivyConf, user: String): String = {
    var candidatePrincipal: String = null
    val ldapDomain = conf.get(LivyConf.THRIFT_LDAP_AUTHENTICATION_DOMAIN)
    if (hasDomain(user) || isDn(user)) {
      candidatePrincipal = user
    } else if (StringUtils.isNotBlank(ldapDomain)) {
      candidatePrincipal = user + "@" + ldapDomain
    }
    candidatePrincipal
  }
}

