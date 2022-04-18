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
	"fmt"
)

import (
	"github.com/spaolacci/murmur3"
)

// LOAD_FACTOR
/* in order to reduce the conflict of hash
 * hash array can be LOAD_FACTOR times larger than nodePool
 */
const (
	LOAD_FACTOR = 5 // 减少hash冲突
)

// index table of hashSet
// hashSet的索引表
type hashArray []int32

// make a new hashArray and init it
// 创建一个新的hashArray并初始化它
// 元素值记录的是node_pool的下标，如果hash冲突记录的是node_pool中最后一个冲突的元素下标值
func newHashArray(indexSize int) hashArray {
	ha := make(hashArray, indexSize)
	for i := 0; i < indexSize; i += 1 {
		ha[i] = -1
	}

	return ha
}

type HashSet struct {
	// nodePool的索引表
	ha hashArray // hashArray, the index table for nodePool
	// 能存储元素数量
	haSize int // hashArray size
	// 是否固定元素大小
	isFixKeyLen bool // fixed element size or not

	// 管理hashSet的元素
	np *nodePool // nodePool manage the elements of hashSet

	// hash函数
	hashFunc func(key []byte) uint64 //function for hash
}

// NewHashSet creates a newHashSet
//
// PARAMS:
//   - elemNum: max element num of hashSet
//   - elemSize: maxSize of hashKey after it converted to []byte
//   - isFixKeyLen: fixed element size or not
//   - hashFunc: hash function
//
// RETURNS:
//  - (*HashSet, nil), if success
//  - (nil, error), if fail
// NewHashSet创建一个NewHashSet
// 参数:
// - elemNum: hashSet的最大元素数
// - elemSize: hashKey转换为[]字节后的最大大小
// - isFixKeyLen:是否固定元素大小
// - hashFunc:哈希函数
// 返回:
// - (*HashSet, nil)，如果成功
// - (nil, error)，如果失败
func NewHashSet(elemNum int, elemSize int, isFixKeyLen bool,
	hashFunc func([]byte) uint64) (*HashSet, error) {
	if elemNum <= 0 || elemSize <= 0 {
		return nil, fmt.Errorf("elementNum/elementSize must > 0")
	}

	hashSet := new(HashSet)

	// hashArray is larger in order to reduce hash conflict
	// hashArray变大是为了减少hash冲突
	hashSet.haSize = elemNum * LOAD_FACTOR
	hashSet.isFixKeyLen = isFixKeyLen
	hashSet.ha = newHashArray(hashSet.haSize)

	// create nodePool 创建nodePool
	hashSet.np = newNodePool(elemNum, elemSize, isFixKeyLen)

	// if hashFunc is not given, use default murmur Hash
	if hashFunc != nil {
		hashSet.hashFunc = hashFunc
	} else {
		hashSet.hashFunc = murmur3.Sum64
	}

	return hashSet, nil
}

// Add - add an element into the set
//
// PARAMS:
//   - key: []byte, element of the set
//
// RETURNS:
//   - nil, if succeed
//   - error, if fail
// Add -在集合中添加一个元素
// 参数:
// - key:[]字节，元素的集合
// 返回:
// - nil，如果成功
// - 错误，如果失败
func (set *HashSet) Add(key []byte) error {
	// check the whether hashSet if full
	if set.Full() {
		return fmt.Errorf("hashSet: Set is full")
	}

	// validate hashKey
	err := set.np.validateKey(key)
	if err != nil {
		return err
	}

	// 1. calculate the hash num
	// 计算哈希值
	hashNum := set.hashFunc(key) % uint64(set.haSize)

	// 2. check if the key slice exist
	// 检查键片是否存在
	if set.exist(hashNum, key) {
		return nil
	}

	// 3. add the key into nodePool
	// 添加
	head := set.ha[hashNum] // hash冲突有值 不冲突=-1
	newHead, err := set.np.add(head, key)
	if err != nil {
		return err
	}

	// 4. point to the new list head node
	// 设置node_pool中位置
	set.ha[hashNum] = newHead

	return nil
}

// Remove removes an element from the hashSet
//
// PARAMS:
//   - key: []byte, element of the set
//
// RETURNS:
//   - nil, if succeed
//   - error, if fail
// 移除hashSet中的一个元素
// 参数:
// - key:[]字节，元素的集合
// 返回:
// - nil，如果成功
// - 错误，如果失败
func (set *HashSet) Remove(key []byte) error {
	// validate hashKey
	err := set.np.validateKey(key)
	if err != nil {
		return err
	}
	//1. calculate the hash num
	hashNum := set.hashFunc(key) % uint64(set.haSize)

	//2. remove key from hashNode
	head := set.ha[hashNum]
	// -1说明不存在
	if head == -1 {
		return nil
	}
	newHead := set.np.del(head, key)

	//3. point to the new list head node
	set.ha[hashNum] = newHead

	return nil
}

// Exist checks if the element exist in Set
// 检查该元素是否存在于Set中
func (set *HashSet) Exist(key []byte) bool {
	//validate hashKey
	err := set.np.validateKey(key)
	if err != nil {
		return false
	}

	hashNum := set.hashFunc(key) % uint64(set.haSize)
	return set.exist(hashNum, key)
}

// exist checks the []byte exist in the giving list head
// 校验key是否已存在
func (set *HashSet) exist(hashNum uint64, key []byte) bool {
	head := set.ha[hashNum]
	return set.np.exist(head, key)
}

// Len returns element Num of hashSet
func (set *HashSet) Len() int {
	return set.np.elemNum()
}

// Full checks if the hashSet full or not
// 检查hashSet是否已满
func (set *HashSet) Full() bool {
	return set.np.full()
}
