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

package byte_pool

import "fmt"

// BytePool 元素长度不固定的内存池
type BytePool struct {
	buf    []byte
	length []uint32 // 元素下标的key长度
	// 最大的单个元素长度
	maxElemSize int // max length of element
	// 能存储的元素数
	maxElemNum int // max element num
}

// NewBytePool creates a new BytePool
//
// PARAMS:
//   - elemNum: int, the max element num of BytePool
//   - maxElemSize: int, the max length of each element
//
// RETURNS:
//   - a pointer point to the BytePool
// NewBytePool创建一个新的BytePool
// 参数:
// - elemNum: int，字节池的最大元素数
// - maxElemSize: int，每个元素的最大长度
// 返回:
// -一个指向字节池的指针
func NewBytePool(elemNum int, maxElemSize int) *BytePool {
	pool := new(BytePool)
	pool.buf = make([]byte, elemNum*maxElemSize)
	pool.length = make([]uint32, elemNum)
	pool.maxElemSize = maxElemSize
	pool.maxElemNum = elemNum

	return pool
}

// Set sets the index node of BytePool with key
//
// PARAMS:
//   - index: index of the byte Pool
//   - key: []byte key
// 在index位置设置key
func (pool *BytePool) Set(index int32, key []byte) error {
	if int(index) >= pool.maxElemNum {
		return fmt.Errorf("index out of range %d %d", index, pool.maxElemNum)
	}

	if len(key) > pool.maxElemSize {
		return fmt.Errorf("elemSize large than maxSize %d %d", len(key), pool.maxElemSize)
	}

	start := int(index) * pool.maxElemSize // 起始位置
	copy(pool.buf[start:], key)

	pool.length[index] = uint32(len(key))

	return nil
}

// Get the byte slice
//
// PARAMS:
//   - index: int, index of the BytePool
//
// RETURNS:
//   - key: []byte type store in the BytePool
// 获取index位置的key
func (pool *BytePool) Get(index int32) []byte {
	start := int(index) * pool.maxElemSize
	end := start + int(pool.length[index])

	return pool.buf[start:end]
}

// MaxElemSize returns the space allocate for each element
func (pool *BytePool) MaxElemSize() int {
	return pool.maxElemSize
}
