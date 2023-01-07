/*
 * Copyright (c) 2016 Lonelycoder AB
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

static __inline void mem_wrptr(ir_unit_t *iu, uint32_t offset, void *ptr)
{
  mem_wr32((char *)iu->iu_mem + offset, ptr ? (char *)ptr - (char *)iu->iu_mem : 0, iu);
}

static __inline void *mem_rdptr(ir_unit_t *iu, uint32_t offset)
{
  uint32_t p = mem_rd32((char *)iu->iu_mem + offset, iu);
  if(p)
    return (char *)iu->iu_mem + p;
  return NULL;
}




#ifdef VMIR_USE_TLSF

#include "tlsf.h"

static void
vmir_heap_init(ir_unit_t *iu)
{
  iu->iu_heap = tlsf_create(iu->iu_mem + iu->iu_heap_start,
                            iu->iu_memsize - iu->iu_heap_start);
}


static void *
vmir_heap_malloc(ir_unit_t *iu, int size)
{
  void *p = tlsf_malloc(iu->iu_heap, size);
  iu->iu_heap_usage += tlsf_block_size(p);
  iu->iu_stats.peak_heap_size =
    VMIR_MAX(iu->iu_stats.peak_heap_size, iu->iu_heap_usage);
  if(p == NULL)
    vmir_log(iu, VMIR_LOG_ERROR, "malloc(%d) failed", size);

  return p;
}

static void
vmir_heap_free(ir_unit_t *iu, void *ptr)
{
  if(ptr != NULL)
    iu->iu_heap_usage -= tlsf_block_size(ptr);
  tlsf_free(iu->iu_heap, ptr);
}

static void *
vmir_heap_realloc(ir_unit_t *iu, void *ptr, int size)
{
  if(ptr != NULL)
    iu->iu_heap_usage -= tlsf_block_size(ptr);
  void *p = tlsf_realloc(iu->iu_heap, ptr, size);
  if(p) {
    iu->iu_heap_usage += tlsf_block_size(p);
    iu->iu_stats.peak_heap_size =
      VMIR_MAX(iu->iu_stats.peak_heap_size, iu->iu_heap_usage);
  } else {

    if(size)
      vmir_log(iu, VMIR_LOG_ERROR, "realloc(%d) failed", size);
  }
  return p;
}





static void
walker_print(void* ptr, size_t size, int used, void* user)
{
  printf("%p +%zd %s\n", ptr, size, used ? "Used" : "Free");
}

static void
vmir_heap_print0(void *pool)
{
  printf(" --- Heap allocation dump (TLSF) ---\n");
  tlsf_walk_heap(pool, walker_print, NULL);
}



typedef struct walkeraux {
  void (*fn)(void *opaque, uint32_t addr, uint32_t size,
             int inuse);
  void *opaque;
  ir_unit_t *iu;
} walkeraux_t;


static void
walker_ext(void *ptr, size_t size, int used, void* user)
{
  walkeraux_t *aux = user;
  aux->fn(aux->opaque, (uint32_t)(ptr - aux->iu->iu_mem), size, used);
}


void
vmir_walk_heap(ir_unit_t *iu,
               void (*fn)(void *opaque, uint32_t addr, uint32_t size,
                          int inuse),
               void *opaque)
{
  walkeraux_t aux;
  aux.fn = fn;
  aux.opaque = opaque;
  aux.iu = iu;
  tlsf_walk_heap(iu->iu_heap, walker_ext, &aux);
}



#else

typedef struct heap_block {
  int hb_magic;
#define HEAP_MAGIC_FREE   0xf4eef4ee
#define HEAP_MAGIC_ALLOC   0xa110ced

  int hb_size;  // Size of block including this header struct
  TAILQ_ENTRY(heap_block) hb_link;
} heap_block_t;

TAILQ_HEAD(heap_block_queue, heap_block);

typedef struct heap {
  struct heap_block_queue h_blocks;
} heap_t;



static void
vmir_heap_init(ir_unit_t *iu)
{
  int size = iu->iu_memsize - iu->iu_heap_start;
  heap_t *h = (heap_t *)((char *)iu->iu_mem + iu->iu_heap_start);
  iu->iu_heap = h;
  TAILQ_INIT(&h->h_blocks);

  heap_block_t *hb = (void *)(h + 1);

  hb->hb_size = size - sizeof(heap_t);
  hb->hb_magic = HEAP_MAGIC_FREE;
  TAILQ_INSERT_TAIL(&h->h_blocks, hb, hb_link);
}


static void *
vmir_heap_malloc(ir_unit_t *iu, int size)
{
  heap_t *h = iu->iu_heap;
  heap_block_t *hb;
  size += sizeof(heap_block_t);
  size = VMIR_ALIGN(size, 16);

  TAILQ_FOREACH(hb, &h->h_blocks, hb_link) {
    if(hb->hb_magic != HEAP_MAGIC_FREE)
      continue;

    if(size <= hb->hb_size) {
      int remain = hb->hb_size - size;
      if(remain < sizeof(heap_block_t) * 2) {
        size = hb->hb_size;
      } else {
        heap_block_t *split = (heap_block_t *)((char *)hb + size);
        split->hb_magic = HEAP_MAGIC_FREE;
        split->hb_size = remain;
        TAILQ_INSERT_AFTER(&h->h_blocks, hb, split, hb_link);
      }

      hb->hb_magic = HEAP_MAGIC_ALLOC;
      hb->hb_size = size;
      return (void *)(hb + 1);
    }
  }
  return NULL;
}


static void
vmir_heap_merge_next(heap_t *h, heap_block_t *hb)
{
  heap_block_t *next = TAILQ_NEXT(hb, hb_link);
  if(next == NULL || next->hb_magic != HEAP_MAGIC_FREE)
    return;
  assert(next > hb);
  TAILQ_REMOVE(&h->h_blocks, next, hb_link);
  hb->hb_size += next->hb_size;
}

static void
vmir_heap_free(ir_unit_t *iu, void *ptr)
{
  if(ptr == NULL)
    return;
  heap_t *h = iu->iu_heap;
  heap_block_t *hb = ptr;
  hb--;
  assert(hb->hb_magic == HEAP_MAGIC_ALLOC);
  hb->hb_magic = HEAP_MAGIC_FREE;

  vmir_heap_merge_next(h, hb);
  heap_block_t *prev = TAILQ_PREV(hb, heap_block_queue, hb_link);
  if(prev != NULL) {
    assert(prev < hb);
    vmir_heap_merge_next(h, prev);
  }
}

static int
vmir_heap_usable_size(void *ptr)
{
  heap_block_t *hb = ptr;
  hb--;
  assert(hb->hb_magic == HEAP_MAGIC_ALLOC);
  return hb->hb_size - sizeof(heap_block_t);
}

static void *
vmir_heap_realloc(ir_unit_t *iu, void *ptr, int size)
{
  void *n = NULL;
  if(size) {
    int cursize = vmir_heap_usable_size(ptr);
    if(size < cursize)
      return ptr;

    n = vmir_heap_malloc(iu, size);
    if(n == NULL)
      return NULL;

    if(ptr != NULL)
      memcpy(n, ptr, cursize);
  }
  vmir_heap_free(iu, ptr);
  return n;
}

static void
vmir_heap_print0(ir_unit_t *iu)
{
  heap_block_t *hb;
  heap_t *h = iu->iu_heap;
  printf(" --- Heap allocation dump ---\n");
  TAILQ_FOREACH(hb, &h->h_blocks, hb_link) {
    printf("%s 0x%x bytes\n",
           hb->hb_magic == HEAP_MAGIC_ALLOC ? "use " :
           hb->hb_magic == HEAP_MAGIC_FREE  ? "free" :
           "????",
           hb->hb_size);
  }
}


#endif


#define MEMTRACE(fmt, ...) // printf(fmt)

static int
vmir_malloc(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t size = vmir_vm_arg32(&rf);
  MEMTRACE("malloc(%d) = ...\n", size);
  void *p = vmir_heap_malloc(iu, size);
  vmir_vm_retptr(ret, p, iu);
  MEMTRACE("malloc(%d) = 0x%x\n", size, *(uint32_t *)ret);
  return 0;
}

static int
vmir_calloc(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t nmemb = vmir_vm_arg32(&rf);
  uint32_t size = vmir_vm_arg32(&rf);
  MEMTRACE("calloc(%d, %d) = ...\n", nmemb, size);
  void *p = vmir_heap_malloc(iu, size * nmemb);
  if(p != NULL)
    memset(p, 0, size * nmemb);
  vmir_vm_retptr(ret, p, iu);
  MEMTRACE("calloc(%d, %d) = 0x%x\n", nmemb, size, *(uint32_t *)ret);
  return 0;
}

static int
vmir_free(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t ptr = vmir_vm_arg32(&rf);
  if(ptr == 0)
    return 0;
  MEMTRACE("free(0x%x)\n", ptr);
  vmir_heap_free(iu, (char *)iu->iu_mem + ptr);
  return 0;
}

static int
vmir_realloc(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t ptr = vmir_vm_arg32(&rf);
  uint32_t size = vmir_vm_arg32(&rf);

  MEMTRACE("realloc(0x%x, %d) = ...\n", ptr, size);
  void *p = vmir_heap_realloc(iu, ptr ? (char *)iu->iu_mem + ptr : NULL, size);
  vmir_vm_retptr(ret, p, iu);
  MEMTRACE("realloc(0x%x, %d) = 0x%x\n", ptr, size, *(uint32_t *)ret);
  return 0;
}

static int
vmir_heap_print(void *ret, const void *rf, ir_unit_t *iu)
{
  vmir_heap_print0(iu);
  return 0;
}


/*--------------------------------------------------------------------
 * Misc
 */


static int
vmir_toupper(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t c = vmir_vm_arg32(&rf);
  if(c >= 'a' && c <= 'z')
    c -= 32;
  vmir_vm_ret32(ret, c);
  return 0;
}

static int
vmir_tolower(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t c = vmir_vm_arg32(&rf);
  if(c >= 'A' && c <= 'Z')
    c += 32;
  vmir_vm_ret32(ret, c);
  return 0;
}

static int
vmir_isprint(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t c = vmir_vm_arg32(&rf);
  c &= 0x7f;
  c = (c >= ' ' && c < 127);
  vmir_vm_ret32(ret, c);
  return 0;
}


static int
vmir_isdigit(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t c = vmir_vm_arg32(&rf);
  vmir_vm_ret32(ret, c >= '0' && c <= '9');
  return 0;
}


static int
vmir_atoi(void *ret, const void *rf, ir_unit_t *iu)
{
  const char *str = vmir_vm_ptr(&rf, iu);
  int r = atoi(str);
  vmir_vm_ret32(ret, r);
  return 0;
}

static int
vmir_getpid(void *ret, const void *rf, ir_unit_t *iu)
{
  vmir_vm_ret32(ret, 1);
  return 0;
}



/*-----------------------------------------------------------------------
 * Other stdio
 */

#define FMT_TYPE_INT    1
#define FMT_TYPE_INT64  2
#define FMT_TYPE_PTR    3
#define FMT_TYPE_STR    4
#define FMT_TYPE_DOUBLE 5


static void
dofmt2(void (*output)(void *opaque, const char *str, int len),
       void *opaque,
       const char *start, const char *end, int num_field_args,
       int type, const void **va, ir_unit_t *iu)
{
  const void *vacopy = *va;
  size_t len = end - start;
  char *fmt = alloca(len + 1);
  char tmpbuf[100];
  void *alloc = NULL;
  char *dst;
  size_t dz = sizeof(tmpbuf);
  memcpy(fmt, start, len);
  fmt[len] = 0;
  dst = tmpbuf;

  while(1) {
    int n = -1;
    int l1, l2;
    *va = vacopy;
    switch(type) {
    case FMT_TYPE_INT:
      switch(num_field_args) {
      case 0:
        n = snprintf(dst, dz, fmt, vmir_vm_vaarg32(va, iu));
        break;
      case 1:
        l1 = vmir_vm_vaarg32(va, iu);
        n = snprintf(dst, dz, fmt, l1, vmir_vm_vaarg32(va, iu));
        break;
      case 2:
        l1 = vmir_vm_vaarg32(va, iu);
        l2 = vmir_vm_vaarg32(va, iu);
        n = snprintf(dst, dz, fmt, l1, l2, vmir_vm_vaarg32(va, iu));
        break;
      default:
        goto done;
      }
      break;

    case FMT_TYPE_INT64:
      switch(num_field_args) {
      case 0:
        n = snprintf(dst, dz, fmt, vmir_vm_vaarg64(va, iu));
        break;
      case 1:
        l1 = vmir_vm_vaarg32(va, iu);
        n = snprintf(dst, dz, fmt, l1, vmir_vm_vaarg64(va, iu));
        break;
      case 2:
        l1 = vmir_vm_vaarg32(va, iu);
        l2 = vmir_vm_vaarg32(va, iu);
        n = snprintf(dst, dz, fmt, l1, l2, vmir_vm_vaarg64(va, iu));
        break;
      default:
        goto done;
      }
      break;

    case FMT_TYPE_PTR:
      switch(num_field_args) {
      case 0:
        n = snprintf(dst, dz, fmt, (void *)(intptr_t)vmir_vm_vaarg32(va, iu));
        break;
      case 1:
        l1 = vmir_vm_vaarg32(va, iu);
        n = snprintf(dst, dz, fmt, l1,
                     (void *)(intptr_t)vmir_vm_vaarg32(va, iu));
        break;
      case 2:
        l1 = vmir_vm_vaarg32(va, iu);
        l2 = vmir_vm_vaarg32(va, iu);
        n = snprintf(dst, dz, fmt, l1, l2,
                     (void *)(intptr_t)vmir_vm_vaarg32(va, iu));
        break;
      default:
        goto done;
      }
      break;

    case FMT_TYPE_STR:
      switch(num_field_args) {
      case 0:
        n = snprintf(dst, dz, fmt, vmir_vm_vaptr(va, iu));
        break;
      case 1:
        l1 = vmir_vm_vaarg32(va, iu);
        n = snprintf(dst, dz, fmt, l1, vmir_vm_vaptr(va, iu));
        break;
      case 2:
        l1 = vmir_vm_vaarg32(va, iu);
        l2 = vmir_vm_vaarg32(va, iu);
        n = snprintf(dst, dz, fmt, l1, l2, vmir_vm_vaptr(va, iu));
        break;
      default:
        goto done;
      }
      break;

    case FMT_TYPE_DOUBLE:
      switch(num_field_args) {
      case 0:
        n = snprintf(dst, dz, fmt, vmir_vm_vaarg_dbl(va, iu));
        break;
      case 1:
        l1 = vmir_vm_vaarg32(va, iu);
        n = snprintf(dst, dz, fmt, vmir_vm_vaarg32(va, iu),
                     vmir_vm_vaarg_dbl(va, iu));
        break;
      case 2:
        l1 = vmir_vm_vaarg32(va, iu);
        l2 = vmir_vm_vaarg32(va, iu);
        n = snprintf(dst, dz, fmt, l1, l2, vmir_vm_vaarg_dbl(va, iu));
        break;
      default:
        goto done;
      }
      break;
    }

    if(n < 0)
      break;

    if(n < dz) {
      output(opaque, dst, n);
      break;
    }

    assert(alloc == NULL);
    dz = n + 1;
    alloc = malloc(dz);
    dst = alloc;
  }

 done:
  free(alloc);
}


// Useful tests at
// https://github.com/wine-mirror/wine/blob/master/dlls/msvcrt/tests/printf.c

#define FMT_FLAGS_LONG  0x1
#define FMT_FLAGS_INT64 0x2


static void
dofmt(void (*output)(void *opaque, const char *str, int len),
      void *opaque, const char *fmt, const void *valist,
      ir_unit_t *iu)
{
  while(*fmt) {
    char c = *fmt;
    if(c != '%') {
      output(opaque, fmt, 1); // xxx: lame, should do long runs of unfmted str
      fmt++;
      continue;
    }
    int num_field_args = 0;
    const char *start = fmt;
    int flags = 0;
    fmt++;
  again:
    c = *fmt++;
  reswitch:
    switch(c) {
    case ' ':
    case '#':
    case '+':
    case '-':
    case '0':
      goto again;
    case '*':
      num_field_args++;
      goto again;

    case '.':
      if((c = *fmt++) == '*') {
        goto reswitch;
      }

      while(c >= '0' && c <= '9')
        c = *fmt++;
      goto reswitch;

    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
      do {
        c = *fmt++;
      } while(c >= '0' && c <= '9');
      goto reswitch;
    case 'z':
      flags = 0;
      goto again;
    case 'l':
      if(flags & FMT_FLAGS_LONG)
        flags |= FMT_FLAGS_INT64;
      else
        flags |= FMT_FLAGS_LONG;
      goto again;

    case 'q':
      flags |= FMT_FLAGS_INT64;
      goto again;

    case 'c':
      dofmt2(output, opaque, start, fmt, num_field_args, FMT_TYPE_INT,
             &valist, iu);
      break;

    case 'O':
    case 'o':
    case 'D':
    case 'd':
    case 'i':
    case 'U':
    case 'u':
    case 'X':
    case 'x':
      if(flags & FMT_FLAGS_INT64) {
        dofmt2(output, opaque, start, fmt, num_field_args, FMT_TYPE_INT64,
               &valist, iu);
      } else {
        dofmt2(output, opaque, start, fmt, num_field_args, FMT_TYPE_INT,
               &valist, iu);
      }
      break;

    case 'e':
    case 'E':
    case 'f':
    case 'g':
    case 'G':
      dofmt2(output, opaque, start, fmt, num_field_args, FMT_TYPE_DOUBLE,
             &valist, iu);
      break;

    case 'p':
      dofmt2(output, opaque, start, fmt, num_field_args, FMT_TYPE_PTR,
             &valist, iu);
      break;

    case 's':
      dofmt2(output, opaque, start, fmt, num_field_args, FMT_TYPE_STR,
             &valist, iu);
      break;

    case 0:
      return;

    default:
      output(opaque, &c, 1);
      break;
    }
  }
}

static const void *
vmir_valist(const void **rf, ir_unit_t *iu)
{
  if(iu->iu_mode == VMIR_WASM)
    return (const void *)vmir_vm_ptr(rf, iu);
  else
    return *(void **)vmir_vm_ptr(rf, iu);
}


typedef struct fmt_sn_aux {
  char *dst;
  unsigned int remain;
  unsigned int total;
} fmt_sn_aux_t;



static void
fmt_sn(void *opaque, const char *str, int len)
{
  fmt_sn_aux_t *aux = opaque;
  aux->total += len;
  if(aux->remain == 0)
    return;

  // Figure out how much to copy, we always reserve one byte for trailing 0
  int to_copy = VMIR_MIN(aux->remain - 1, len);

  memcpy(aux->dst, str, to_copy);
  aux->dst += to_copy;
  aux->remain -= to_copy;
}


static int
vmir_vsnprintf(void *ret, const void *rf, ir_unit_t *iu)
{
  char *dst = vmir_vm_ptr(&rf, iu);
  int dstlen = vmir_vm_arg32(&rf);
  const char *fmt = vmir_vm_ptr(&rf, iu);
  const void *va_rf = vmir_valist(&rf, iu);

  fmt_sn_aux_t aux;
  aux.dst = dst;
  aux.remain = dstlen;
  aux.total = 0;
  dofmt(fmt_sn, &aux, fmt, va_rf, iu);
  // Nul termination
  if(aux.remain)
    *aux.dst = 0;
  vmir_vm_ret32(ret, aux.total);
  return 0;
}

static int
vmir_snprintf(void *ret, const void *rf, ir_unit_t *iu)
{
  char *dst = vmir_vm_ptr(&rf, iu);
  int dstlen = vmir_vm_arg32(&rf);
  const char *fmt = vmir_vm_ptr(&rf, iu);

  if(iu->iu_mode == VMIR_WASM)
    rf = (const void *)vmir_vm_ptr(&rf, iu);

  fmt_sn_aux_t aux;
  aux.dst = dst;
  aux.remain = dstlen;
  aux.total = 0;

  dofmt(fmt_sn, &aux, fmt, rf, iu);

  // Nul termination
  if(aux.remain)
    *aux.dst = 0;
  vmir_vm_ret32(ret, aux.total);
  return 0;
}



static int
vmir_vsprintf(void *ret, const void *rf, ir_unit_t *iu)
{
  char *dst = vmir_vm_ptr(&rf, iu);
  const char *fmt = vmir_vm_ptr(&rf, iu);
  const void *va_rf = vmir_valist(&rf, iu);

  fmt_sn_aux_t aux;
  aux.dst = dst;
  aux.remain = INT32_MAX;
  aux.total = 0;
  dofmt(fmt_sn, &aux, fmt, va_rf, iu);

  // Nul termination
  if(aux.remain)
    *aux.dst = 0;
  vmir_vm_ret32(ret, aux.total);
  return 0;

}

static int
vmir_sprintf(void *ret, const void *rf, ir_unit_t *iu)
{
  char *dst = vmir_vm_ptr(&rf, iu);
  const char *fmt = vmir_vm_ptr(&rf, iu);

  if(iu->iu_mode == VMIR_WASM)
    rf = (const void *)vmir_vm_ptr(&rf, iu);

  fmt_sn_aux_t aux;
  aux.dst = dst;
  aux.remain = INT32_MAX;
  aux.total = 0;
  dofmt(fmt_sn, &aux, fmt, rf, iu);

  // Nul termination
  if(aux.remain)
    *aux.dst = 0;
  vmir_vm_ret32(ret, aux.total);
  return 0;

}


static void
fmt_file(void* opaque, const char* str, int len)
{
  int *total = opaque;
  *total += len;
  puts(str);
}

static int
vmir_vprintf(void *ret, const void *rf, ir_unit_t *iu)
{
  const char *fmt = vmir_vm_ptr(&rf, iu);
  const void *va_rf = vmir_valist(&rf, iu);

  int total = 0;
  dofmt(fmt_file, &total, fmt, va_rf, iu);

  vmir_vm_ret32(ret, total);
  return 0;
}


static int
vmir_printf(void *ret, const void *rf, ir_unit_t *iu)
{
  const char *fmt = vmir_vm_ptr(&rf, iu);

  if(iu->iu_mode == VMIR_WASM)
    rf = (const void *)vmir_vm_ptr(&rf, iu);

  int total = 0;
  dofmt(fmt_file, &total, fmt, rf, iu);

  vmir_vm_ret32(ret, total);
  return 0;
}


static int
vmir_getenv(void *ret, const void *rf, ir_unit_t *iu)
{
  vmir_vm_ret32(ret, 0);
  return 0;
}


/*-----------------------------------------------------------------------
 * libc string functions
 */
static int
vmir_strtok_r(void *retreg, const void *rf, ir_unit_t *iu)
{
  char *str         = vmir_vm_ptr(&rf, iu);
  const char *delim = vmir_vm_ptr(&rf, iu);
  uint32_t nextp = vmir_vm_arg32(&rf);

  if(str == NULL)
    str = mem_rdptr(iu, nextp);

  str += strspn(str, delim);

  if(*str == '\0') {
    vmir_vm_ret32(retreg, 0);
    return 0;
  }

  char *ret = str;
  str += strcspn(str, delim);
  if(*str)
    *str++ = '\0';

  mem_wrptr(iu, nextp, str);

  vmir_vm_retptr(retreg, ret, iu);
  return 0;
}


static int
vmir_strtok(void *retreg, const void *rf, ir_unit_t *iu)
{
  char *str         = vmir_vm_ptr(&rf, iu);
  const char *delim = vmir_vm_ptr(&rf, iu);

  if(str == NULL)
    str = iu->iu_strtok_tmp;

  str += strspn(str, delim);

  if(*str == '\0') {
    vmir_vm_ret32(retreg, 0);
    return 0;
  }

  char *ret = str;
  str += strcspn(str, delim);
  if(*str)
    *str++ = '\0';

  iu->iu_strtok_tmp = str;

  vmir_vm_retptr(retreg, ret, iu);
  return 0;
}



/*-----------------------------------------------------------------------
 * C++
 */

static int
vmir_cxa_guard_acquire(void *ret, const void *rf, ir_unit_t *iu)
{
  uint8_t *p = vmir_vm_ptr(&rf, iu);
  if(*p == 0) {
    *p = 1;
    vmir_vm_ret32(ret, 1);
  } else {
    vmir_vm_ret32(ret, 0);
  }
  return 0;
}

static int
vmir_cxa_guard_release(void *ret, const void *rf, ir_unit_t *iu)
{
  return 0;
}

static int
vmir__cxa_at_exit(void *ret, const void *rf, ir_unit_t *iu)
{
  return 0;
}


/*-----------------------------------------------------------------------
 * C++ exception handling
 */

typedef struct vmir_cxx_exception {
  uint32_t next;
  int handlers;
  uint32_t destructor;

} vmir_cxx_exception_t;

static int
vmir_llvm_eh_typeid_for(void *ret, const void *rf, ir_unit_t *iu)
{
  vmir_vm_ret32(ret, vmir_vm_arg32(&rf));
  return 0;
}

static int
vmir___cxa_allocate_exception(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t size = vmir_vm_arg32(&rf);
  void *p = vmir_heap_malloc(iu, size + sizeof(vmir_cxx_exception_t));
  memset(p, 0, sizeof(vmir_cxx_exception_t));
  vmir_vm_retptr(ret, (char *)p + sizeof(vmir_cxx_exception_t), iu);
  return 0;
}

static int
vmir___cxa_free_exception(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t x = vmir_vm_arg32(&rf) - sizeof(vmir_cxx_exception_t);
  vmir_heap_free(iu, (char *)iu->iu_mem + x);
  return 0;
}

static int
vmir___cxa_begin_catch(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t x = vmir_vm_arg32(&rf);
  uint32_t x2 = x - sizeof(vmir_cxx_exception_t);
  vmir_cxx_exception_t *exc = (vmir_cxx_exception_t *)((char *)iu->iu_mem + x2);

  if(exc->handlers < 0) {
    exc->handlers = -exc->handlers + 1;
  } else {
    exc->handlers++;
    iu->iu_exception.uncaught--;
  }

  exc->next = iu->iu_exception.caught;
  iu->iu_exception.caught = x2;
  vmir_vm_ret32(ret, x);
  return 0;
}


static int
vmir___cxa_end_catch(void *ret, const void *rf, ir_unit_t *iu)
{
  vmir_cxx_exception_t *exc = (vmir_cxx_exception_t *)((char *)iu->iu_mem + iu->iu_exception.caught);

  if(--exc->handlers == 0) {
    iu->iu_exception.caught = exc->next;
    vmir_heap_free(iu, exc);
  }
  return 0;
}

static int
vmir___cxa_throw(void *ret, const void *rf, ir_unit_t *iu)
{
  iu->iu_exception.exception = vmir_vm_arg32(&rf);
  iu->iu_exception.type_info = vmir_vm_arg32(&rf);

  vmir_cxx_exception_t *exc =
    (vmir_cxx_exception_t *)((char *)iu->iu_mem + iu->iu_exception.exception - sizeof(vmir_cxx_exception_t));
  exc->destructor = vmir_vm_arg32(&rf);
  assert(exc->destructor == 0); // Not really supported (yet)
  iu->iu_exception.uncaught++;
  return 1;
}


static int
vmir_std_terminate(void *ret, const void *rf, ir_unit_t *iu)
{
  vm_stop(iu, VM_STOP_UNCAUGHT_EXCEPTION, 0);
  return 0;
}



static int
vmir_set_data_breakpoint(void *ret, const void *rf, ir_unit_t *iu)
{
  iu->iu_data_breakpoint = vmir_vm_ptr_nullchk(&rf, iu);
  printf("Data breakpoint: 0x%zx\n", (char *)iu->iu_data_breakpoint - (char *)iu->iu_mem);
  return 0;
}



static int
vmir_libc_hexdump(void *ret, const void *rf, ir_unit_t *iu)
{
  uint32_t addr = vmir_vm_arg32(&rf);
  uint32_t size = vmir_vm_arg32(&rf);
  printf("Hexdump of 0x%x\n", addr);
  vmir_hexdump("hexdump", (char *)iu->iu_mem + addr, size);
  return 0;
}


static int
vmir_libc_traceback(void *ret, const void *rf, ir_unit_t *iu)
{
#ifndef VM_NO_STACK_FRAME
  vmir_traceback(iu, "__vmir_traceback");
#endif
  return 0;
}


#define FN_EXT(a, b)   { .name = a, .extfunc = b }

static const vmir_function_tab_t libc_funcs[] = {

  FN_EXT("exit", vm_exit),
  FN_EXT("abort", vm_abort),
  FN_EXT("llvm.trap", vm_abort),
  FN_EXT("__cxa_guard_abort", vm_abort),

  FN_EXT("getpid", vmir_getpid),
  FN_EXT("atoi", vmir_atoi),
  FN_EXT("toupper", vmir_toupper),
  FN_EXT("tolower", vmir_tolower),
  FN_EXT("isprint", vmir_isprint),
  FN_EXT("isdigit", vmir_isdigit),

  FN_EXT("malloc",  vmir_malloc),
  FN_EXT("free",    vmir_free),
  FN_EXT("realloc", vmir_realloc),
  FN_EXT("calloc",  vmir_calloc),

  FN_EXT("vsnprintf",  vmir_vsnprintf),
  FN_EXT("snprintf",  vmir_snprintf),
  FN_EXT("vsprintf",  vmir_vsprintf),
  FN_EXT("sprintf",  vmir_sprintf),
  FN_EXT("vprintf",  vmir_vprintf),
  FN_EXT("printf",  vmir_printf),

  FN_EXT("strtok_r", vmir_strtok_r),
  FN_EXT("strtok", vmir_strtok),

  FN_EXT("getenv",  vmir_getenv),

  FN_EXT("__vmir_heap_print",  vmir_heap_print),
  FN_EXT("__vmir_set_data_breakpoint",  vmir_set_data_breakpoint),
  FN_EXT("__vmir_hexdump",  vmir_libc_hexdump),
  FN_EXT("__vmir_traceback",  vmir_libc_traceback),

  // C++ low level stuff

  FN_EXT("__cxa_guard_acquire", vmir_cxa_guard_acquire),
  FN_EXT("__cxa_guard_release", vmir_cxa_guard_release),

  FN_EXT("_ZdlPv",  vmir_free),    // operator delete(void*)
  FN_EXT("_Znwj",   vmir_malloc),  // operator new(unsigned int)
  FN_EXT("_ZdaPv",  vmir_free),    // operator delete[](void*)
  FN_EXT("_Znaj",   vmir_malloc),  // operator new[](unsigned int)

  FN_EXT("__cxa_atexit", vmir__cxa_at_exit),

  FN_EXT("__cxa_allocate_exception", vmir___cxa_allocate_exception),
  FN_EXT("__cxa_free_exception", vmir___cxa_free_exception),
  FN_EXT("__cxa_begin_catch", vmir___cxa_begin_catch),
  FN_EXT("__cxa_end_catch", vmir___cxa_end_catch),
  FN_EXT("__cxa_throw", vmir___cxa_throw),
  FN_EXT("llvm.eh.typeid.for", vmir_llvm_eh_typeid_for),
  FN_EXT("_ZSt9terminatev", vmir_std_terminate),
};



/**
 *
 */
vm_ext_function_t *
vmir_function_tab_lookup(const char *function,
                         const vmir_function_tab_t *array, int length)
{
  for(int i = 0; i < length; i++) {
    const vmir_function_tab_t *ft = array + i;
    if(!strcmp(function, ft->name)) {
      return ft->extfunc;
    }
  }
  return NULL;
}

/**
 *
 */
vm_ext_function_t *
vmir_default_external_function_resolver(const char *function, void *opaque)
{
  return vmir_function_tab_lookup(function, libc_funcs,
                                  VMIR_ARRAYSIZE(libc_funcs));
}




/**
 *
 */
static void
libc_initialize(ir_unit_t *iu)
{
}

static void VMIR_UNUSED
libc_terminate(ir_unit_t *iu)
{
}


uint32_t
vmir_mem_alloc(ir_unit_t *iu, uint32_t size, void *hostaddr_)
{
  void **hostaddr = hostaddr_;
  void *p = vmir_heap_malloc(iu, size);
  if(p == NULL) {
    if(hostaddr)
      *hostaddr = NULL;
    return 0;
  }
  if(hostaddr)
    *hostaddr = p;
  return (char *)p - (char *)iu->iu_mem;
}

void
vmir_mem_free(ir_unit_t *iu, uint32_t addr)
{
  vmir_heap_free(iu, (char *)iu->iu_mem + addr);
}
