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

typedef struct Header {
  size_t size;
  void* prev;
  char free;
} Header;

typedef struct FreeNode {
  struct FreeNode* next;
  struct FreeNode* prev;
} FreeNode;

// All blocks must have a specified minimum alignment.
// The alignment requirement (from config.h) is >= 8 bytes.
#ifndef ALIGNMENT
  #define ALIGNMENT 8
#endif

// Rounds up to the nearest multiple of ALIGNMENT.
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))

// The smallest aligned size that will hold a size_t value.
#define HEADER_SIZE (ALIGN(sizeof(struct Header)))

// Assumes no malloc larger than 2^20
#define MAX_LIST 31
#define MIN_LIST 3
#define THRESHOLD 256
#define HEAD_SIZE(i) (size_t)((2 + (i & 1)) << (MIN_LIST + (i >> 1)))
#define HEAD_INDEX(size) (int)(2*log2(size) - 2*(MIN_LIST+1));
#define GET_HEADER(p) (Header*)((char*)p - HEADER_SIZE)

// p (uint64_t)((char*)manPtr - (((sizeof(size_t) + sizeof(uint64_t) + sizeof(char)) + (8-1)) & ~(8-1)) - sizeof(size_t))

int mallocCount;
void* prevRequest;
char manInList;
void* heapPtr;
void* manPtr;
void* nextPtr;
int memAvail;

//16,24,32,48,64,96,128...
FreeNode* freeListHeads[MAX_LIST];
int freeListHeadsCount[MAX_LIST];
int freeListHeadsReq[MAX_LIST];

void printMCount(){
  printf("Mem_sbrk Calls: %d\n", mallocCount);
}

void printMemBlocks(){
  //  for(int i = 0; i < MAX_LIST; i++) {
  //printf("Block %d: %d(inserts), %d(removals)\n", HEAD_SIZE(i), freeListHeadsCount[i], freeListHeadsReq[i]);
  //}
}

// init - Initialize the malloc package.  Called once before any other
// calls are made.  Since this is a very simple implementation, we just
// return success.
int my_init() {
  mallocCount = 0;
  prevRequest = NULL;
  manInList = 0;
  heapPtr = NULL;
  manPtr = NULL;
  nextPtr = NULL;
  memAvail = 0;
  for (int i = 0; i < MAX_LIST; i++) {
    freeListHeads[i] = NULL;
    freeListHeadsCount[i] = 0;
    freeListHeadsReq[i] = 0;
  }
  return 0;
}

void remove_free_node(FreeNode* node) {
  //remove prevRequest from free list
  if (node->next != NULL) {
    node->next->prev = node->prev;
  }
  if (node->prev != NULL) {
    node->prev->next = node->next;
  } else {
    Header* header = GET_HEADER(node);
    int index = HEAD_INDEX(header->size);
    freeListHeads[index] = node->next;
  }
}

void add_free_node(FreeNode* node, int i) {
  if (freeListHeads[i] != NULL) {
    freeListHeads[i]->prev = node;
  }
  node->next = freeListHeads[i];
  node->prev = NULL;
  freeListHeads[i] = node;
  freeListHeadsCount[i]++;
}

void set_header(void* p, size_t size, void* prevP, char free) {
  Header* header = GET_HEADER(p);
  header->size =  size;
  header->prev =  prevP;
  header->free = free;
}

void* my_malloc_get_mem(size_t size) {
  // check how much memory we already have
  if (memAvail <= 0) {
    // no available memory; request entire memory block
    mallocCount++;
    int alignedSize = ALIGN(size + HEADER_SIZE);
    void* p = mem_sbrk(alignedSize);
    if (p == (void*) - 1) {
      return NULL;
    } else {
      void* newPtr = (void*)((char*)p + HEADER_SIZE);
      set_header(newPtr, size, manPtr, 0);
      prevRequest = newPtr;
      manPtr = prevRequest;
      manInList = 0;
      heapPtr = (void*)((char*)prevRequest + size);
      //printf("New Malloc: %lu(ptr), %d(requested)\n", (uint64_t)newPtr, size);
      return newPtr;
    }
  } else if ((int) size - memAvail >= 0) {
    // allocate enough space to complete block if worth it
    void* p = mem_sbrk((int) size - memAvail);
    //printf("Heap Reuse: %lu(ptr), %d(requested), %d(available)\n", (uint64_t)manPtr, size, memAvail);
    memAvail = 0;
    if (p == (void*) - 1) {
      return NULL;
    }
    Header* header = GET_HEADER(manPtr);
    set_header(manPtr, size, header->prev, 0);
    prevRequest = manPtr;
    manInList = 0;
    heapPtr = manPtr + size;
    return manPtr;
  } else {
    // use some of the available memory
    Header* header = GET_HEADER(manPtr);
    set_header(manPtr, size, header->prev, 0);
    //printf("Heap Reuse: %lu(ptr), %d(requested), %d(available)\n", (uint64_t)manPtr, size, memAvail);
    void* newPtr = manPtr;
    void* newManPtr = (void*)((char*)manPtr + size + HEADER_SIZE);
    memAvail = (uint64_t)heapPtr - (uint64_t)newManPtr;
    manInList = 0;
    if (memAvail > 0) {
      manPtr = newManPtr;
      set_header(manPtr, NULL, newPtr, 1);
    }
    return newPtr;
  }
}

void* my_malloc(size_t size) {
  //TODO(magendanz) more optimal with size as the storage size
  size_t blockSize = size;
  // if size fits in a freelist, grab block
  int i = 0;
  while (i < MAX_LIST) {
    size_t headSize = HEAD_SIZE(i);
    if (blockSize <= headSize) {
      FreeNode* head = freeListHeads[i];
      if (head == NULL) {
	//TODO(magendanz) break up larger block
        void* a = my_malloc_get_mem(headSize);
	return a;
      }
      freeListHeads[i] = head->next;
      if (freeListHeads[i] != NULL) {
        freeListHeads[i]->prev = NULL;
      }
      Header* header = GET_HEADER(head);
      header->free = 0;
      freeListHeadsReq[i]++;
      if ((uint64_t)head > (uint64_t)manPtr){
	continue;
      }
      //printf("Node Used: %lu(ptr), %d(size)\n", (uint64_t)head, header->size);
      return head;
    }
    i++;
  }
  return NULL;
}

// free and add to free nodes
void my_free(void* ptr) {
  Header* header = GET_HEADER(ptr);
  //printf("Free: %lu(ptr), %d(freed)\n", (uint64_t)ptr, header->size);
  header->free = 1;
  // stick into freelist
  size_t size = header->size;
  FreeNode* newNode = (FreeNode*)ptr;
  int i = 0;
  while (i < MAX_LIST) {
    size_t headSize = HEAD_SIZE(i);
    if (size <= headSize) {
      if (freeListHeads[i] != NULL) {
        freeListHeads[i]->prev = newNode;
      }
      add_free_node(newNode, i);
      break;
    }
    i++;
  }
  if (ptr == manPtr) {
    manInList = 1;
  }

  // move manPtr to lowest free location on heap
  Header* manHeader = GET_HEADER(manPtr);
  if (manHeader->free && manHeader->prev != NULL) {
    Header* subManHeader = GET_HEADER(manHeader->prev);
    if (subManHeader->free) {
      if (manPtr == prevRequest && manInList) {
	remove_free_node(manPtr);
	manInList = 0;
      }
      nextPtr = manHeader->prev;
      Header* nextHeader = GET_HEADER(nextPtr);
      while (nextPtr != NULL && nextHeader->free) {
	remove_free_node(nextPtr);
	manPtr = nextPtr;
	nextPtr = nextHeader->prev;
	nextHeader = GET_HEADER(nextPtr);
      }
      memAvail = (uint64_t)heapPtr - (uint64_t)manPtr;
      //printf("New manPtr: %lu\n", (uint64_t)manPtr);
    }
  }
}

// realloc - Implemented simply in terms of malloc and free
void* my_realloc(void* ptr, size_t size) {
  void* newptr;
  Header* header = GET_HEADER(ptr);
  size_t copy_size = header->size;
  
  // if current memory block fits the size change, do nothing
  // TODO(magendanz) not space efficient if size dramatically shrinking
  if (size <= copy_size && size >= (copy_size/2)) {
    return ptr;
  }
  // if current memory block was most recently allocated, allocate extra 
  // space needed and return same block
  if (ptr == prevRequest) {
    size_t v = size;
    // round up to next 2^n
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v |= v >> 32;
    v++;
    mem_sbrk(v - copy_size);
    header->size = v;
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

#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

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
