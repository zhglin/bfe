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

// FixedBytePool 元素长度固定的内存池
type FixedBytePool struct {
	buf []byte
	// 单个元素的长度
	elemSize int // element length
	// 元素数量
	maxElemNum int // max element num
}

// NewFixedBytePool creates a new FixedBytePool
//
// PARAMS:
//   - elemNum: int, the max element num of FixedBytePool
//   - elemSize: int, the max length of each element
//
// RETURNS:
//   - a pointer point to the FixedBytePool
//创建一个新的FixedBytePool
//参数:
// - elemNum: int, FixedBytePool的最大元素数
// - elemSize: int，每个元素的最大长度
//返回:
// - 指向FixedBytePool的指针
func NewFixedBytePool(elemNum int, elemSize int) *FixedBytePool {
	pool := new(FixedBytePool)
	pool.buf = make([]byte, elemNum*elemSize)
	pool.elemSize = elemSize
	pool.maxElemNum = elemNum

	return pool
}

// Set sets the index node of FixedBytePool with key
//
// PARAMS:
//   - index: index of the byte Pool
//   - key: []byte key
// index位置写入key
func (pool *FixedBytePool) Set(index int32, key []byte) error {
	if int(index) >= pool.maxElemNum {
		return fmt.Errorf("index out of range %d %d", index, pool.maxElemNum)
	}

	if len(key) != pool.elemSize {
		return fmt.Errorf("length must be %d while %d", pool.elemSize, len(key))
	}
	start := int(index) * pool.elemSize // 字节的起始位置
	copy(pool.buf[start:], key)

	return nil
}

// Get the byte slice of giving index and length
//
// PARAMS:
//   - index: int, index of the FixedBytePool
//
// RETURNS:
//   - key: []byte type store in the FixedBytePool
// 读取index位置的key
func (pool *FixedBytePool) Get(index int32) []byte {
	start := int(index) * pool.elemSize // 起始位置
	end := start + pool.elemSize        // 结束位置

	return pool.buf[start:end]
}

// MaxElemSize return the space allocate for each element
// 返回每个元素的空间分配
func (pool *FixedBytePool) MaxElemSize() int {
	return pool.elemSize
}
