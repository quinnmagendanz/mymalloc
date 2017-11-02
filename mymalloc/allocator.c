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

// All blocks must have a specified minimum alignment.
// The alignment requirement (from config.h) is >= 8 bytes.
#ifndef ALIGNMENT
  #define ALIGNMENT 8
#endif

// Rounds up to the nearest multiple of ALIGNMENT.
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))

// The smallest aligned size that will hold a size_t value.
#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

// Assumes no malloc larger than 2^20
#define MAX_LIST 16
#define MIN_LIST 4
#define THRESHOLD .75
#define HEAD_SIZE(i) (size_t)(1 << (MIN_LIST + (i)))
#define MARK_SIZE(p, size) *(size_t*)((char*)p - SIZE_T_SIZE) = size
#define GET_SIZE(p) *(size_t*)((char*)p - SIZE_T_SIZE)

typedef struct FreeNode {
  struct FreeNode* next;
  struct FreeNode* prev;
  size_t size;
} FreeNode;

int mallocCount;
void* prevRequest;
char prevRequestFree;

//8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096
FreeNode* freeListHeads[MAX_LIST];

int getMCount(){
  return mallocCount;
}

// init - Initialize the malloc package.  Called once before any other
// calls are made.  Since this is a very simple implementation, we just
// return success.
int my_init() {
  mallocCount = 0;
  prevRequest = NULL;
  prevRequestFree = 0;
  for (int i = 0; i < MAX_LIST; i++) {
    freeListHeads[i] = NULL;
  }
  return 0;
}

// size must be an aligned value
void* my_malloc_get_mem(size_t size) {
  // assert(size == ALIGN(size));

  // if most recent heap allocation is free, use it
  if (prevRequestFree) {
    FreeNode* node = (FreeNode*)prevRequest;
    int memNeeded = (int)size - (int)node->size;
    // only reuse if close to size already
    if (abs(memNeeded) <= size*THRESHOLD) {
      prevRequestFree = 0;
      //remove prevRequest from free list
      if (node->next != NULL) {
        node->next->prev = node->prev;
      }
      if (node->prev != NULL) {
        node->prev->next = node->next;
      } else {
        int index = log2(node->size) - MIN_LIST; //TODO(magendanz) can be faster
        freeListHeads[index] = node->next;
      }

      if (memNeeded <= 0) {
        return (void*)node;
      } else {
        mem_sbrk(memNeeded);
        MARK_SIZE(prevRequest, size);
        printf("Heap Reuse: %zu(requested), %zu(old)\n", size, node->size);
        return (void*)node;
      }
    }
  }

  int aligned_size = ALIGN(size + SIZE_T_SIZE);
  void* p = mem_sbrk(aligned_size);
  if (p == (void*) - 1) { // error
    return NULL;
  } else {
    *(size_t*)p = size;
    void* newptr = (void*)((char*)p + SIZE_T_SIZE);
    prevRequest = newptr;
    prevRequestFree = 0;
    //printf("New Malloc: %d(requested)\n", size);
    return newptr;
  }
}

void* my_malloc(size_t size) {
  mallocCount++;

  // if size fits in a freelist, grab block
  int i = 0;
  while (i < MAX_LIST) {
    size_t headSize = HEAD_SIZE(i);
    if (size <= headSize) {
      FreeNode* head = freeListHeads[i];
      if (head == NULL) { // bin is empty
        void* a = my_malloc_get_mem(headSize);
        assert(GET_SIZE(a) >= size);
        return a;
      }
      freeListHeads[i] = head->next;
      if (freeListHeads[i] != NULL) {
        freeListHeads[i]->prev = NULL;
      }
      MARK_SIZE(head, headSize);
      assert(GET_SIZE(head) >= size);
      if (head == prevRequest) {
        prevRequestFree = 0;
      }
      return head;
    }
    i++;
  }
  return NULL;
}

// free - Freeing a block adds it into the appropriate free list
void my_free(void* ptr) {
  size_t size = GET_SIZE(ptr);
  FreeNode* newNode = (FreeNode*)ptr;

  // stick into free list
  int i = 0;
  while (i < MAX_LIST) {
    size_t headSize = HEAD_SIZE(i);
    if (size <= headSize) {
      if (freeListHeads[i] != NULL) {
        freeListHeads[i]->prev = newNode;
      }
      newNode->next = freeListHeads[i];
      newNode->prev = NULL;
      newNode->size = headSize;
      freeListHeads[i] = newNode;
      if (prevRequest == ptr) {
        prevRequestFree = 1;
      }
      return;
    }
    i++;
  }
}

// realloc - Implemented simply in terms of malloc and free
void* my_realloc(void* ptr, size_t size) {
  void* newptr;
  size_t copy_size = GET_SIZE(ptr);
  
  // if current memory block fits the size change, do nothing
  // TODO(magendanz) not space efficient if size dramatically shrinking
  if (size <= copy_size && size >= (copy_size/2)) {
    return ptr;
  }
  // if current memory block was most recently allocated, allocate extra 
  // space needed and return same block
  if (ptr == prevRequest) {
    size_t v = size;
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v |= v >> 32;
    v++;
    mem_sbrk(v - copy_size);
    MARK_SIZE(ptr, v);
    return ptr;
  }

  newptr = my_malloc(size);
  if (NULL == newptr) {
    return NULL;
  }

  if (size < copy_size) {
    copy_size = size;
  }
  memcpy(newptr, ptr, copy_size);

  my_free(ptr);
  return newptr;
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
     size = ALIGN(*(size_t*)p + SIZE_T_SIZE);
     p += size;
   }

   if (p != hi) {
     printf("Bad headers did not end at heap_hi!\n");
     printf("heap_lo: %p, heap_hi: %p, size: %lu, p: %p\n", lo, hi, size, p);
     return -1;
   }

   return 0;
 }


// init - Initialize the malloc package.  Called once before any other
// calls are made.  Since this is a very simple implementation, we just
// return success.
int my_init_old() {
  return 0;
}

//  malloc - Allocate a block by incrementing the brk pointer.
//  Always allocate a block whose size is a multiple of the alignment.
void* my_malloc_old(size_t size) {
  // We allocate a little bit of extra memory so that we can store the
  // size of the block we've allocated.  Take a look at realloc to see
  // one example of a place where this can come in handy.
  int aligned_size = ALIGN(size + SIZE_T_SIZE);

  // Expands the heap by the given number of bytes and returns a pointer to
  // the newly-allocated area.  This is a slow call, so you will want to
  // make sure you don't wind up calling it on every malloc.
  void* p = mem_sbrk(aligned_size);

  if (p == (void*) - 1) {
    // Whoops, an error of some sort occurred.  We return NULL to let
    // the client code know that we weren't able to allocate memory.
    return NULL;
  } else {
    // We store the size of the block we've allocated in the first
    // SIZE_T_SIZE bytes.
    *(size_t*)p = size;

    // Then, we return a pointer to the rest of the block of memory,
    // which is at least size bytes long.  We have to cast to uint8_t
    // before we try any pointer arithmetic because voids have no size
    // and so the compiler doesn't know how far to move the pointer.
    // Since a uint8_t is always one byte, adding SIZE_T_SIZE after
    // casting advances the pointer by SIZE_T_SIZE bytes.
    return (void*)((char*)p + SIZE_T_SIZE);
  }
}

// free - Freeing a block does nothing.
void my_free_old(void* ptr) {
}

// realloc - Implemented simply in terms of malloc and free
void* my_realloc_old(void* ptr, size_t size) {
  void* newptr;
  size_t copy_size;

  // Allocate a new chunk of memory, and fail if that allocation fails.
  newptr = my_malloc(size);
  if (NULL == newptr) {
    return NULL;
  }

  // Get the size of the old block of memory.  Take a peek at my_malloc(),
  // where we stashed this in the SIZE_T_SIZE bytes directly before the
  // address we returned.  Now we can back up by that many bytes and read
  // the size.
  copy_size = *(size_t*)((uint8_t*)ptr - SIZE_T_SIZE);

  // If the new block is smaller than the old one, we have to stop copying
  // early so that we don't write off the end of the new block of memory.
  if (size < copy_size) {
    copy_size = size;
  }

  // This is a standard library call that performs a simple memory copy.
  memcpy(newptr, ptr, copy_size);

  // Release the old block.
  my_free(ptr);

  // Return a pointer to the new block.
  return newptr;
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
