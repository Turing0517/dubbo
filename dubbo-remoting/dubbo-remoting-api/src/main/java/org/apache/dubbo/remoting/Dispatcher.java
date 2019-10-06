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
package org.apache.dubbo.remoting;

import org.apache.dubbo.common.URL;
import org.apache.dubbo.common.extension.Adaptive;
import org.apache.dubbo.common.extension.SPI;
import org.apache.dubbo.remoting.transport.dispatcher.all.AllDispatcher;

/**
 * ChannelHandlerWrapper (SPI, Singleton, ThreadSafe)线程派发器
 *
 * 如果一些事件处理逻辑可以很快执行完，比如只在内存打一个标记，此时直接在 IO 线程上执行该段逻辑即可。
 * 但如果事件的处理逻辑比较耗时，比如该段逻辑会发起数据库查询或者 HTTP 请求。
 * 此时我们就不应该让事件处理逻辑在 IO 线程上执行，而是应该派发到线程池中去执行。原因也很简单，
 * IO 线程主要用于接收请求，如果 IO 线程被占满，将导致它不能接收新的请求。
 * 需要说明的是，Dispatcher 真实的职责创建具有线程派发能力的 ChannelHandler，
 * 比如 AllChannelHandler、MessageOnlyChannelHandler 和 ExecutionChannelHandler 等，
 * 其本身并不具备线程派发能力。Dubbo 支持 5 种不同的线程派发策略，下面通过一个表格列举一下。
 * 策略	用途
 * all	所有消息都派发到线程池，包括请求，响应，连接事件，断开事件等
 * direct	所有消息都不派发到线程池，全部在 IO 线程上直接执行
 * message	只有请求和响应消息派发到线程池，其它消息均在 IO 线程上执行
 * execution	只有请求消息派发到线程池，不含响应。其它消息均在 IO 线程上执行
 * connection	在 IO 线程上，将连接断开事件放入队列，有序逐个执行，其它消息派发到线程池
 */
@SPI(AllDispatcher.NAME)
public interface Dispatcher {

    /**
     * dispatch the message to threadpool.
     *
     * @param handler
     * @param url
     * @return channel handler
     */
    @Adaptive({Constants.DISPATCHER_KEY, "dispather", "channel.handler"})
    // The last two parameters are reserved for compatibility with the old configuration
    ChannelHandler dispatch(ChannelHandler handler, URL url);

}
