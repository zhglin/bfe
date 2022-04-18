// Copyright (c) 2019 The BFE Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hash_set

import (
	"bytes"
	"fmt"
)

import (
	"github.com/bfenetworks/bfe/bfe_util/byte_pool"
)

/* hash node */
type hashNode struct {
	// hash冲突的链表法
	// 每条冲突链的第一个元素下标都为-1，后续冲突的建下标指向上一个元素下标
	next int32 // link to the next node
}

/* a list of hash node */
type nodePool struct {
	array []hashNode //node array

	// 管理nodePool的freeNode 空闲的node编号
	freeNode int32 // manage the freeNode of nodePool
	// 容量
	capacity int // capacity of nodePool
	// 元素数量
	length int // length of nodePool

	pool byte_pool.IBytePool // reference to []byte pool
}

/*
 * create a new nodePool
 *
 * PARAMS:
 *  - elemNum: max num of elements
 *  - elemSize: max size of each element of hashSet
 *
 * RETURNS:
 *  - pointer to nodePool
 */
// 创建一个新的nodePool
// *参数:
// -elemNum:元素的最大数量
// -elemSize: hashSet中每个元素的最大大小
// 返回:
// -指向nodePool的指针
func newNodePool(elemNum, elemSize int, isFixedKeylen bool) *nodePool {
	np := new(nodePool)

	// make and init node array
	// 创建和初始化节点数组
	np.array = make([]hashNode, elemNum)
	for i := 0; i < elemNum-1; i += 1 {
		np.array[i].next = int32(i + 1) // link to the next node
	}
	// 最后一个元素
	np.array[elemNum-1].next = -1 //initial value == -1, means end of the list

	np.freeNode = 0 //free node start from 0
	np.capacity = elemNum
	np.length = 0

	if isFixedKeylen {
		np.pool = byte_pool.NewFixedBytePool(elemNum, elemSize) // 固定长度
	} else {
		np.pool = byte_pool.NewBytePool(elemNum, elemSize)
	}
	return np
}

/*
 * add
 *  - add key into the list starting from head
 *  - return the new headNode
 *
 * PARAMS:
 *  - head: first node of the list
 *  - key: []byte type
 *
 * RETURNS:
 *  - (newHead, nil), success, new headNode of the list
 *  - (-1, error), if fail
 */
// 添加
// -添加键到列表中，从头部开始
// -返回新的headNode
// 参数:
// - head:上一个head值
// - key:[]字节类型
// 返回:
// - (newHead, nil)，成功，列表的新headNode
// - (-1, error)，如果失败
func (np *nodePool) add(head int32, key []byte) (int32, error) {
	// get a bucket from freeNode List
	// 从freeNode列表中获取一个桶
	node, err := np.getFreeNode()
	if err != nil {
		return -1, err
	}

	np.array[node].next = head
	//set the node with key
	// 设置到底层存储
	np.pool.Set(node, key)

	np.length += 1
	return node, nil
}

/*
 * del
 *  - remove the key([]byte) in the given list
 *  - return the new head of the list
 *
 * PARAMS:
 *  - head: int, the first node of the list
 *  - key: []byte, the key need to be del
 *
 * RETURNS:
 *  - newHead int, the new head node of the list
 */
// 删除指定的key
func (np *nodePool) del(head int32, key []byte) int32 {
	var newHead int32
	// check at the head of List
	// 刚好在head位置
	if np.compare(key, head) == 0 {
		newHead = np.array[head].next // 上一个hash冲突的位置
		np.recycleNode(head)          //recycle the node 回收节点
		return newHead
	}

	// check at the list
	// 冲突了，不在head位置
	pindex := head
	for {
		index := np.array[pindex].next
		if index == -1 { // 说明没有hash冲突，head不相等
			break
		}
		if np.compare(key, index) == 0 {
			np.array[pindex].next = np.array[index].next
			np.recycleNode(index) //recycle the node 找到了删除
			return head
		}
		pindex = index
	}
	return head // 没删掉还返回原值
}

/* del the node, add the node into freeNode list */
// 删除该节点，将该节点添加到freeNode列表中
func (np *nodePool) recycleNode(node int32) {
	index := np.freeNode        // 当前的freeNode下标
	np.freeNode = node          // 设置freeNode
	np.array[node].next = index // freeNode指向之前的freeNode
	np.length -= 1
}

/* check if the key exist in the list */
// 检查该键是否存在于列表中
func (np *nodePool) exist(head int32, key []byte) bool {
	for index := head; index != -1; index = np.array[index].next {
		if np.compare(key, index) == 0 {
			return true
		}
	}
	return false
}

/* get a free node from freeNode list */
// 获取空的存储节点
func (np *nodePool) getFreeNode() (int32, error) {
	if np.freeNode == -1 {
		return -1, fmt.Errorf("NodePool: no more node to use")
	}

	// return freeNode and make freeNode = freeNode.next
	node := np.freeNode
	np.freeNode = np.array[node].next // 最后一个=-1
	np.array[node].next = -1          // 断掉链表关系

	return node, nil
}

/* get node num in use of nodePool */
// 已经存放的元素数量
func (np *nodePool) elemNum() int {
	return np.length
}

/* check if the node Pool is full */
// 是否已满
func (np *nodePool) full() bool {
	return np.length >= np.capacity
}

/* compare the given key with index node */
// 比较i位置的key是否相等
func (np *nodePool) compare(key []byte, i int32) int {
	element := np.element(i)
	return bytes.Compare(key, element)
}

/* get the element of the giving index*/
// 获取i位置的key值
func (np *nodePool) element(i int32) []byte {
	return np.pool.Get(i)
}

/* get the space allocate for each element */
// 获取底层存储的单个元素大小
func (np *nodePool) elemSize() int {
	return np.pool.MaxElemSize()
}

/* check whtether the key is legal for the set */
// 检查key长度是否合法
func (np *nodePool) validateKey(key []byte) error {
	if len(key) <= np.elemSize() {
		return nil
	}
	return fmt.Errorf("element len[%d] > bucketSize[%d]", len(key), np.elemSize())
}
