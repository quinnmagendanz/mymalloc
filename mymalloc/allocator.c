/**
 * Copyright (c) 2015 MIT License by 6.172 Staff
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 **/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "./allocator_interface.h"
#include "./memlib.h"

// Don't call libc malloc!
#define malloc(...) (USE_MY_MALLOC)
#define free(...) (USE_MY_FREE)
#define realloc(...) (USE_MY_REALLOC)

struct Header;
typedef struct Header Header;

struct Header {
  size_t size;
  void* prev;
  char free;
};

struct FreeNode;
typedef struct FreeNode FreeNode;

struct FreeNode {
  struct FreeNode* next;
  struct FreeNode* prev;
};

// All blocks must have a specified minimum alignment.
// The alignment requirement (from config.h) is >= 8 bytes.
#ifndef ALIGNMENT
  #define ALIGNMENT 8
#endif

// Rounds up to the nearest multiple of ALIGNMENT.
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))

// TODO(sophia): does this speed anything up?
size_t headerSize = ALIGN(sizeof(struct Header));
size_t freeNodeSize = ALIGN(sizeof(struct FreeNode));

// The smallest aligned size that will hold a header value.
// TODO(sophia): precompute this?
#define HEADER_SIZE (ALIGN(sizeof(struct Header)))

// The smalles aligned size that will hold a free node (aka smallest block size)
// TODO(sophia): precompute this?
#define FREENODE_SIZE (ALIGN(sizeof(struct FreeNode)))

// Returns a pointer to the header of a block
#define GET_HEADER(p) (Header*)((char*)p - HEADER_SIZE)

#define THRESHOLD 512

// p (uint64_t)((char*)manPtr - (((sizeof(size_t) + sizeof(uint64_t) + sizeof(char)) + (8-1)) & ~(8-1)) - sizeof(size_t))

void* prevRequest;
char manInList;
void* heapPtr;
void* manPtr;
void* nextPtr;
int memAvail;
int acount;
void* tracked;

//16,24,32,48,64,96,128...
FreeNode* smallFreeListHead;
FreeNode* largeFreeListHead;

// init - Initialize the malloc package.  Called once before any other
// calls are made.  Since this is a very simple implementation, we just
// return success.
int my_init() {
  prevRequest = NULL;
  manInList = 0;
  heapPtr = NULL;
  manPtr = NULL;
  nextPtr = NULL;
  memAvail = 0;
  smallFreeListHead = NULL;
  largeFreeListHead = NULL;
  acount = 0;
  tracked = NULL;
  return 0;
}

void remove_free_node(FreeNode* node, size_t size) {
  assert((GET_HEADER(node))->free == 1);
  //remove prevRequest from free list
  if (node->next != NULL) { // node is not the last in free list
    node->next->prev = node->prev;
  }
  if (node->prev != NULL) { // node is not the first in free list
    node->prev->next = node->next;
  } else { // node is the first in free list
    if (size < THRESHOLD) {
      smallFreeListHead = node->next;
    } else {
      largeFreeListHead = node->next;
    }
  }
  (GET_HEADER(node))->free = 0;
}

void add_free_node(FreeNode* node, size_t size) {
  // determine which free list to add the block to
  FreeNode** freeList;
  if (size < THRESHOLD) {
    freeList = &smallFreeListHead;
  } else {
    freeList = &largeFreeListHead;
  }
  // add the block to the beginning of the free list
  if (*freeList != NULL) {
    (*freeList)->prev = node;
  }
  node->next = *freeList;
  node->prev = NULL;
  *freeList = node;
  (GET_HEADER(node))->free = 1;
}

static inline void set_header(void* p, size_t size, void* prevP, char free) {
  Header* header = GET_HEADER(p);
  header->size = size;
  header->prev = prevP;
  header->free = free;
}

static inline void set_header_size(void* p, size_t size) {
  Header* header = GET_HEADER(p);
  header->size = size;
}

static inline void set_header_prev(void* p, void* prevP) {
  Header* header = GET_HEADER(p);
  header->prev = prevP;
}

void split_free_block(FreeNode* ptr, size_t originalSize, size_t blockSize) {
  // create a new header for the leftover block and add to a free list
  size_t newSize = originalSize - blockSize - HEADER_SIZE;
  assert(newSize >= FREENODE_SIZE);
  void* newPtr = (void*)((char*)ptr + blockSize + HEADER_SIZE);        
  set_header(newPtr, newSize, ptr, 1);
  add_free_node(newPtr, newSize);
  // update header with smaller block size
  assert((char*)newPtr - (char*)ptr == blockSize + HEADER_SIZE);
  assert(originalSize == blockSize + HEADER_SIZE + (GET_HEADER(newPtr))->size);
  set_header_size(ptr, blockSize);
  // update header of the next block on the heap (if exists) with proper prev pointer
  void* nextPtr = (void*)((char*)newPtr + newSize + HEADER_SIZE);
  if (nextPtr < my_heap_hi()) {
    set_header_prev(nextPtr, newPtr);
  }
  // update prevRequest
  if (ptr == prevRequest) {
    prevRequest = newPtr;
  }
}

// search a single free list for a block that is at least blockSize large
// TODO(sophia): short-circuit this search using max block sizes w/ maxPrev?
static inline void* search_free_list(FreeNode* freeListHead, size_t blockSize) {
  for (FreeNode* curNode = freeListHead; curNode != NULL; curNode = curNode->next) {
    Header* header = GET_HEADER(curNode);
    assert(header->free == 1);
    if (blockSize <= header->size) {
      size_t original_size = header->size;
      // block is large enough to split
      // TODO(sophia): find a better heuristic for splitting
      if ((header->size < 128 && header->size > 3*blockSize) || (header->size > 2*blockSize)) {
        split_free_block(curNode, header->size, blockSize);
        assert(header->size != original_size);
      }
      // printf("FreeNode Reuse: %lu(ptr), %zu(size)\n", (uint64_t)curNode, blockSize);
      remove_free_node(curNode, original_size);
      assert(header->free == 0);
      return curNode;
    }
  }
  return NULL;
}

// search the free lists for a block that is at least blockSize large
static inline void* search_free_blocks(size_t blockSize) {
  void* freePtr = NULL;
  if (blockSize < THRESHOLD) {
    freePtr = search_free_list(smallFreeListHead, blockSize);
    if (freePtr != NULL) {
      return freePtr;
    }
  }
  freePtr = search_free_list(largeFreeListHead, blockSize);
  return freePtr;
}

void* my_malloc(size_t size) {
  acount += 1;

  size_t blockSize = ALIGN(size);
  if (blockSize <= FREENODE_SIZE) {
    blockSize = FREENODE_SIZE;
  }

  // if size fits in a freelist, grab block
  void* freePtr = search_free_blocks(blockSize);
  if (freePtr != NULL) {
    // Header* header = GET_HEADER(freePtr);
    // assert(header->free == 0);
    return freePtr;
  }

  // no block large enough in free list, request new heap memory
  void* p = mem_sbrk(HEADER_SIZE + blockSize);
  if (p == (void*) - 1) {
    return NULL;
  }
  void* newPtr = (void*)((char*)p + HEADER_SIZE);
  set_header(newPtr, blockSize, prevRequest, 0);
  prevRequest = newPtr;

  // Header* header = GET_HEADER(newPtr);
  // assert(header->free == 0);
  // printf("New Malloc: %lu(ptr), %zu(requested)\n", (uint64_t)newPtr, size);
  return newPtr;
}

void coalesce_right(void* ptr) {
  Header* header = GET_HEADER(ptr);
  Header* rightHeader = (void*)((char*)ptr + header->size);
  if ((void*)rightHeader < mem_heap_hi()) {
    assert(rightHeader->prev == ptr);
    if (rightHeader->free == 1) {
      void* rightPtr = (void*)((char*)rightHeader + HEADER_SIZE);
      remove_free_node(rightPtr, rightHeader->size);
      assert(rightHeader->free == 0);
      size_t newSize = header->size + HEADER_SIZE + rightHeader->size;
      header->size = newSize;
      // TODO(sophia): safety checks to see if falls off heap??? may not matter
      Header* nextHeader = (Header*)((char*)rightPtr + rightHeader->size);
      nextHeader->prev = ptr;
      if (prevRequest == rightPtr) {
        prevRequest = ptr;
      }
    }
  }
}

void* coalesce_left(void* ptr) {
  Header* header = GET_HEADER(ptr);
  if (header->prev != NULL) { // ptr is not the first block on the heap
    void* leftPtr = header->prev;
    Header* leftHeader = GET_HEADER(leftPtr);

    // if the previous block is free
    if (leftHeader->free == 1) {
      remove_free_node(leftPtr, leftHeader->size);
      assert(leftHeader->free == 0);
      size_t newSize = leftHeader->size + HEADER_SIZE + header->size;
      leftHeader->size = newSize;
      // TODO(sophia): safety checks?? does this matter? see coalesce_right
      Header* nextHeader = (Header*)((char*)ptr + header->size);
      nextHeader->prev = leftPtr;
      if (prevRequest == ptr) {
        prevRequest = leftPtr;
      }
      return leftPtr;
    }
  }
  return ptr;
}

void* coalesce(void* ptr) {
  coalesce_right(ptr);
  void* freePtr = coalesce_left(ptr);
  return freePtr;
  // return ptr;
}

// free and add to free nodes
void my_free(void* ptr) {
  // printf("free %p\n", ptr);
  // Header* header = GET_HEADER(ptr);
  // assert(header->free == 0);
  
  // check if adjacent blocks are free
  void* freePtr = coalesce(ptr);
  Header* freeHeader = GET_HEADER(freePtr);
  add_free_node(freePtr, freeHeader->size);
  assert(freeHeader->free == 1);

  // add_free_node(ptr, header->size);
  // assert(header->free == 1);
}

// round up to the next 2^n
// TODO(sophia): we might not need this anymore?
static inline size_t nearestPower2(size_t size) {
  size_t v = size;
  v--;
  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;
  v |= v >> 32;
  v++;
  return v;
}

// realloc - Implemented simply in terms of malloc and free
void* my_realloc(void* ptr, size_t size) {
  void* newPtr;
  Header* header = GET_HEADER(ptr);
  size_t copySize = header->size;

  // if current memory block fits the size change, do nothing
  // TODO(magendanz) not space efficient if size dramatically shrinking
  if (size <= copySize && size >= (copySize/2)) {
    return ptr;
  }
  // if current memory block was most recently allocated, allocate extra 
  // space needed and return same block
  if (ptr == prevRequest) {
    size_t blockSize = ALIGN(size);
    if (blockSize > copySize) {
      mem_sbrk(blockSize - copySize);
      header->size = blockSize;
      //printf("Realloc by expansion: %lu(ptr), %d(requested)\n", (uint64_t)manPtr, v);
      return ptr;
    }
  }
  // we have to find a free block or allocate new memory
  newPtr = my_malloc(size);
  if (newPtr != NULL) {
    if (size < copySize) { //TODO(sophia): is this redundant??
      copySize = size;
    }
    memcpy(newPtr, ptr, copySize);
    my_free(ptr);
  }
  return newPtr;
}

int my_check_old();

int my_check() {
  // size_t header before every block points to either the beginning of the 
  // next block, or the end of the heap.
  if (my_check_old() == -1) return -1;

  //Is every block in the free list marked as free?
  //Are there any contiguous free blocks that could be coalesced?
  //Is every free block actually in the free list?
  //Do the pointers in the free list point to valid free blocks?
  //Do any allocated blocks overlap?
  //Do the pointers in a heap block point to valid heap addresses?

  return 0;
}

//---------------------------------Old Functions-------------------------------

// check - This checks our invariant that the size_t header before every
// block points to either the beginning of the next block, or the end of the
// heap.
 int my_check_old() {
   char* p;
   char* lo = (char*)mem_heap_lo();
   char* hi = (char*)mem_heap_hi() + 1;
   size_t size = 0;

   p = lo;
   while (lo <= p && p < hi) {
     size = ALIGN(*(size_t*)p + HEADER_SIZE);
     p += size;
   }

   if (p != hi) {
     printf("Bad headers did not end at heap_hi!\n");
     printf("heap_lo: %p, heap_hi: %p, size: %lu, p: %p\n", lo, hi, size, p);
     return -1;
   }

   return 0;
 }

// call mem_reset_brk.
void my_reset_brk() {
  mem_reset_brk();
}

// call mem_heap_lo
void* my_heap_lo() {
  return mem_heap_lo();
}

// call mem_heap_hi
void* my_heap_hi() {
  return mem_heap_hi();
}
