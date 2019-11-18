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
package org.apache.livy.server

import scala.collection.mutable.{ArrayBuffer, Set}
import org.apache.livy.LivyConf
import org.apache.livy.LivyConf._
import org.apache.livy.Logging
import org.apache.livy.rsc.RSCConf.Entry.LAUNCHER_ADDRESS
import org.apache.livy.server.recovery.ZooKeeperManager
import org.apache.livy.utils.ConsistentHash

class ServiceWatch(livyConf: LivyConf, dir: String) extends Logging {
  require(ZooKeeperManager.get != null, "Cannot find zookeeper service")
  private val consistentHash =
    new ConsistentHash(livyConf.getInt(LivyConf.HA_CONSISTENT_HASH_REPLICA_NUM))

  private val serverIP = livyConf.get(LAUNCHER_ADDRESS)
  require(serverIP != null, "Please config the livy.rsc.launcher.address")
  private val port = livyConf.getInt(SERVER_PORT)
  consistentHash.addNode(serverIP)

  private val nodeAddListeners = new ArrayBuffer[String => Unit]()
  private val nodeRemoveListeners = new ArrayBuffer[String => Unit]()

  ZooKeeperManager.get.getChildren(dir).foreach(node => consistentHash.addNode(node))
  ZooKeeperManager.get.watchAddNode(dir, nodeAddHandler)
  ZooKeeperManager.get.watchRemoveNode(dir, nodeRemoveHandler)

  def register(): Unit = {
    if (livyConf.getBoolean(THRIFT_SERVER_ENABLED)) {
      val thriftPort = livyConf.getInt(THRIFT_SERVER_PORT)
      ZooKeeperManager.get.createEphemeralNode(
        livyConf.get(THRIFT_ZOOKEEPER_NAMESPACE) + "/" + serverIP, s"$serverIP:$thriftPort")
    }

    ZooKeeperManager.get.createEphemeralNode(dir + "/" + serverIP, s"$serverIP:$port")
  }

  def contains(sessionId: Int): Boolean = {
    // We have added current node into consistentHash
    consistentHash.searchNode(sessionId.toString).get == serverIP
  }

  def getNodes(): Set[String] = {
    consistentHash.getNodes
  }

  def search(sessionId: Int, path: String = dir): (String, Int) = {
    val key = consistentHash.searchNode(sessionId.toString).get
    val hostPort = ZooKeeperManager.get.get[String](path + "/" + key).get.split(":")
    (hostPort(0), hostPort(1).toInt)
  }

  def searchThrift(sessionId: Int): (String, Int) = {
    require(livyConf.getBoolean(THRIFT_SERVER_ENABLED), "Thrift service is not configured")
    search(sessionId, livyConf.get(THRIFT_ZOOKEEPER_NAMESPACE))
  }

  def registerNodeAddListener(f : String => Unit): Unit = {
    nodeAddListeners.append(f)
  }

  def registerNodeRemoveListener(f : String => Unit): Unit = {
    nodeRemoveListeners.append(f)
  }

  private def nodeAddHandler(path: String, host: String): Unit = {
    logger.info("Detect new node add: " + host)
    consistentHash.addNode(host)
    nodeAddListeners.foreach(_(host))
  }

  private def nodeRemoveHandler(path: String, host: String): Unit = {
    logger.info("Detect node removed: " + host)
    consistentHash.removeNode(host)
    nodeRemoveListeners.foreach(_(host))
  }
}
