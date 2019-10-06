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
package org.apache.dubbo.rpc.cluster.loadbalance;

import org.apache.dubbo.common.URL;
import org.apache.dubbo.rpc.Invocation;
import org.apache.dubbo.rpc.Invoker;
import org.apache.dubbo.rpc.RpcStatus;

import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

/**
 * LeastActiveLoadBalance
 * <p>
 * Filter the number of invokers with the least number of active calls and count the weights and quantities of these invokers.
 * If there is only one invoker, use the invoker directly;
 * if there are multiple invokers and the weights are not the same, then random according to the total weight;
 * if there are multiple invokers and the same weight, then randomly called.
 * LeastActiveLoadBalance 翻译过来是最小活跃数负载均衡。活跃调用数越小，表明该服务提供者效率越高，单位时间内可处理更多的请求。
 * 此时应优先将请求分配给该服务提供者。在具体实现中，每个服务提供者对应一个活跃数 active。
 * 初始情况下，所有服务提供者活跃数均为0。每收到一个请求，活跃数加1，完成请求后则将活跃数减1。
 * 在服务运行一段时间后，性能好的服务提供者处理请求的速度更快，因此活跃数下降的也越快，
 * 此时这样的服务提供者能够优先获取到新的服务请求、这就是最小活跃数负载均衡算法的基本思想。
 * 除了最小活跃数，LeastActiveLoadBalance 在实现上还引入了权重值。
 * 所以准确的来说，LeastActiveLoadBalance 是基于加权最小活跃数算法实现的。
 * 举个例子说明一下，在一个服务提供者集群中，有两个性能优异的服务提供者。
 * 某一时刻它们的活跃数相同，此时 Dubbo 会根据它们的权重去分配请求，权重越大，获取到新请求的概率就越大。
 * 如果两个服务提供者权重相同，此时随机选择一个即可。
 */
public class LeastActiveLoadBalance extends AbstractLoadBalance {

    public static final String NAME = "leastactive";

    /**
     * 1.遍历 invokers 列表，寻找活跃数最小的 Invoker
     * 2.如果有多个 Invoker 具有相同的最小活跃数，此时记录下这些 Invoker 在 invokers 集合中的下标，
     * 并累加它们的权重，比较它们的权重值是否相等
     * 3.如果只有一个 Invoker 具有最小的活跃数，此时直接返回该 Invoker 即可
     * 4.如果有多个 Invoker 具有最小活跃数，且它们的权重不相等，此时处理方式和 RandomLoadBalance 一致
     * 5.如果有多个 Invoker 具有最小活跃数，但它们的权重相等，此时随机返回一个即可
     * @param invokers
     * @param url
     * @param invocation
     * @param <T>
     * @return
     */
    @Override
    protected <T> Invoker<T> doSelect(List<Invoker<T>> invokers, URL url, Invocation invocation) {
        // Number of invokers
        int length = invokers.size();
        // The least active value of all invokers 最小的活跃数
        int leastActive = -1;
        // The number of invokers having the same least active value (leastActive)
        //具有相同"最下活跃数"的服务提供者（Invoker）数量
        int leastCount = 0;
        // The index of invokers having the same least active value (leastActive)
        //leastIndexes用于记录具有相同"最小活跃数"的Invoker，在Invokers列表中的下标信息
        int[] leastIndexes = new int[length];
        // the weight of every invokers
        //每个invoker的权重
        int[] weights = new int[length];
        // The sum of the warmup weights of all the least active invokes
        //总权重
        int totalWeight = 0;
        // The weight of the first least active invoke
        /**
         * 第一个最小活跃数的invoker权重值，用于与其他具有相同最小活跃数的Invoker的权重进行对比
         * 以检测是否"所有具有相同最小活跃数的Invoker的权重"均相等
         */
        int firstWeight = 0;
        // Every least active invoker has the same weight value?
        boolean sameWeight = true;


        // Filter out all the least active invokers
        //遍历invokers列表
        for (int i = 0; i < length; i++) {
            Invoker<T> invoker = invokers.get(i);
            // Get the active number of the invoke
            //获取Invoker对应的活跃数
            int active = RpcStatus.getStatus(invoker.getUrl(), invocation.getMethodName()).getActive();
            // Get the weight of the invoke configuration. The default value is 100.
            //获取权重
            int afterWarmup = getWeight(invoker, invocation);
            // save for later use
            weights[i] = afterWarmup;
            // If it is the first invoker or the active number of the invoker is less than the current least active number
            //发现更小的活跃数，重新开始
            if (leastActive == -1 || active < leastActive) {
                // Reset the active number of the current invoker to the least active number
                //使用当前活跃数active更新最小活跃数leastActive
                leastActive = active;
                // Reset the number of least active invokers
                //更新leastCount 为1
                leastCount = 1;
                // Put the first least active invoker first in leastIndexes
                //记录当前下标值到leastIndexes中
                leastIndexes[0] = i;
                // Reset totalWeight
                totalWeight = afterWarmup;
                // Record the weight the first least active invoker
                firstWeight = afterWarmup;
                // Each invoke has the same weight (only one invoker here)
                sameWeight = true;
                // If current invoker's active value equals with leaseActive, then accumulating.

            } else if (active == leastActive) {
                //当前Invoker的活跃数active与最小活跃数leastActive
                // Record the index of the least active invoker in leastIndexes order
                //在leastIndexes中记录下当前Invoker在invokers集合中的下标
                leastIndexes[leastCount++] = i;
                // Accumulate the total weight of the least active invoker
                //累加权重
                totalWeight += afterWarmup;
                /**
                 * 检测当前Invoker的权重与firstWeight是否相等
                 * 不相等则将sameWeight置为false
                 */
                // If every invoker has the same weight?
                if (sameWeight && i > 0
                        && afterWarmup != firstWeight) {
                    sameWeight = false;
                }
            }
        }
        // Choose an invoker from all the least active invokers
        //当只有一个Invoker具有最小活跃数，此时直接返回该Invoker即可
        if (leastCount == 1) {
            // If we got exactly one invoker having the least active value, return this invoker directly.
            return invokers.get(leastIndexes[0]);
        }
        //有多个Invoker具有相同的最小活跃数，但它们之间的权重不同
        if (!sameWeight && totalWeight > 0) {
            // If (not every invoker has the same weight & at least one invoker's weight>0), select randomly based on 
            // totalWeight.
            //随机生成一个 [ 0，totalWeight)之间的数字
            int offsetWeight = ThreadLocalRandom.current().nextInt(totalWeight);
            /**
             * 循环让随机数减去具有最小活跃数的invoker的权重值
             * 当offset小于等于0是，返回相应的Invoker
             */
            // Return a invoker based on the random value.
            for (int i = 0; i < leastCount; i++) {
                int leastIndex = leastIndexes[i];
                //获取权重值，并让随机数减去权重值
                offsetWeight -= weights[leastIndex];
                if (offsetWeight < 0) {
                    return invokers.get(leastIndex);
                }
            }
        }
        // If all invokers have the same weight value or totalWeight=0, return evenly.
        //如果权重相同或权重为0时，随机返回一个Invoker
        return invokers.get(leastIndexes[ThreadLocalRandom.current().nextInt(leastCount)]);
    }
}