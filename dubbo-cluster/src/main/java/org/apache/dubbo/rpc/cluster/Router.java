/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.dubbo.rpc.cluster;

import org.apache.dubbo.common.URL;
import org.apache.dubbo.rpc.Invocation;
import org.apache.dubbo.rpc.Invoker;
import org.apache.dubbo.rpc.RpcException;

import java.util.List;

/**
 * Router. (SPI, Prototype, ThreadSafe)
 * <p>
 * <a href="http://en.wikipedia.org/wiki/Routing">Routing</a>
 * 服务目录在刷新 Invoker 列表的过程中，会通过 Router 进行服务路由，筛选出符合路由规则的服务提供者。
 * 在详细分析服务路由的源码之前，先来介绍一下服务路由是什么。服务路由包含一条路由规则，路由规则决定了服务消费者的调用目标，
 * 即规定了服务消费者可调用哪些服务提供者。Dubbo 目前提供了三种服务路由实现，分别为条件路由 ConditionRouter、
 * 脚本路由 ScriptRouter 和标签路由 TagRouter。其中条件路由是我们最常使用的，
 * @see org.apache.dubbo.rpc.cluster.Cluster#join(Directory)
 * @see org.apache.dubbo.rpc.cluster.Directory#list(Invocation)
 */
public interface Router extends Comparable<Router> {

    int DEFAULT_PRIORITY = Integer.MAX_VALUE;

    /**
     * Get the router url.
     *
     * @return url
     */
    URL getUrl();

    /**
     * Filter invokers with current routing rule and only return the invokers that comply with the rule.
     *
     * @param invokers   invoker list
     * @param url        refer url
     * @param invocation invocation
     * @return routed invokers
     * @throws RpcException
     */
    <T> List<Invoker<T>> route(List<Invoker<T>> invokers, URL url, Invocation invocation) throws RpcException;


    /**
     * Notify the router the invoker list. Invoker list may change from time to time. This method gives the router a
     * chance to prepare before {@link Router#route(List, URL, Invocation)} gets called.
     *
     * @param invokers invoker list
     * @param <T>      invoker's type
     */
    default <T> void notify(List<Invoker<T>> invokers) {

    }

    /**
     * To decide whether this router need to execute every time an RPC comes or should only execute when addresses or
     * rule change.
     *
     * @return true if the router need to execute every time.
     */
    boolean isRuntime();

    /**
     * To decide whether this router should take effect when none of the invoker can match the router rule, which
     * means the {@link #route(List, URL, Invocation)} would be empty. Most of time, most router implementation would
     * default this value to false.
     *
     * @return true to execute if none of invokers matches the current router
     */
    boolean isForce();

    /**
     * Router's priority, used to sort routers.
     *
     * @return router's priority
     */
    int getPriority();

    @Override
    default int compareTo(Router o) {
        if (o == null) {
            throw new IllegalArgumentException();
        }
        return Integer.compare(this.getPriority(), o.getPriority());
    }
}
