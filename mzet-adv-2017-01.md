### Summary

Multiple memory corruption issues (heap-based buffer overflow, invalid memory write & read) were found in Artifex MuPDF ver. 1.12.0.

```
Affected Software: Artifex MuPDF in version 1.12.0
Assigned CVE-ID: CVE-2017-17858
```

### Technical Details

**Steps to reproduce invalid memory write issue (malformed input: [in1.pdf](mzet-adv-2017-01/in1.pdf)):**

```
$ ./mupdf-1.12-dest-asan/bin/mutool info in1.pdf
```

ASAN log:

```
==4170==ERROR: AddressSanitizer: SEGV on unknown address 0x601ecb417a70 (pc 0x00000068a1d6 bp 0x7ffef4d2a180 sp 0x7ffef4d2a140 T0)
==4170==The signal is caused by a WRITE memory access.
    #0 0x68a1d5 in pdf_prime_xref_index source/pdf/pdf-xref.c:1210
    #1 0x68a2ed in pdf_load_xref source/pdf/pdf-xref.c:1238
    #2 0x68b807 in pdf_init_document source/pdf/pdf-xref.c:1371
    #3 0x6925b2 in pdf_open_document source/pdf/pdf-xref.c:2285
    #4 0x444ba5 in pdfinfo_info source/tools/pdfinfo.c:976
    #5 0x44538a in pdfinfo_main source/tools/pdfinfo.c:1041
    #6 0x403aa5 in main source/tools/mutool.c:127
    #7 0x7fdbde1bcf69 in __libc_start_main (/usr/lib/libc.so.6+0x20f69)
    #8 0x403339 in _start (/home/fuzz/mupdf-1.12-dest-asan/bin/mutool+0x403339)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV source/pdf/pdf-xref.c:1210 in pdf_prime_xref_index
==4170==ABORTING
```

**Steps to reproduce heap-based buffer overflow issue (malformed input: [in2.pdf](mzet-adv-2017-01/in2.pdf)):**

```
$ ./mupdf-1.12-dest-asan/bin/mutool info in2.pdf
```

ASAN log:

```
=================================================================
==7635==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6040000004f8 at pc 0x000000681a11 bp 0x7ffd06af1420 sp 0x7ffd06af1410
WRITE of size 40 at 0x6040000004f8 thread T0
    #0 0x681a10 in ensure_solid_xref source/pdf/pdf-xref.c:211
    #1 0x682846 in pdf_get_xref_entry source/pdf/pdf-xref.c:324
    #2 0x68a305 in pdf_load_xref source/pdf/pdf-xref.c:1240
    #3 0x68b807 in pdf_init_document source/pdf/pdf-xref.c:1371
    #4 0x6925b2 in pdf_open_document source/pdf/pdf-xref.c:2285
    #5 0x444ba5 in pdfinfo_info source/tools/pdfinfo.c:976
    #6 0x44538a in pdfinfo_main source/tools/pdfinfo.c:1041
    #7 0x403aa5 in main source/tools/mutool.c:127
    #8 0x7f7c92294f69 in __libc_start_main (/usr/lib/libc.so.6+0x20f69)
    #9 0x403339 in _start (/home/fuzz/mupdf-1.12-dest-asan/bin/mutool+0x403339)

0x6040000004f8 is located 0 bytes to the right of 40-byte region [0x6040000004d0,0x6040000004f8)
allocated by thread T0 here:
    #0 0x7f7c92c74860 in __interceptor_malloc /build/gcc/src/gcc/libsanitizer/asan/asan_malloc_linux.cc:62
    #1 0x54356d in fz_malloc_default source/fitz/memory.c:227
    #2 0x542771 in do_scavenging_malloc source/fitz/memory.c:22
    #3 0x542e51 in fz_calloc source/fitz/memory.c:124
    #4 0x6816fe in ensure_solid_xref source/pdf/pdf-xref.c:190
    #5 0x682846 in pdf_get_xref_entry source/pdf/pdf-xref.c:324
    #6 0x68a305 in pdf_load_xref source/pdf/pdf-xref.c:1240
    #7 0x68b807 in pdf_init_document source/pdf/pdf-xref.c:1371
    #8 0x6925b2 in pdf_open_document source/pdf/pdf-xref.c:2285
    #9 0x444ba5 in pdfinfo_info source/tools/pdfinfo.c:976
    #10 0x44538a in pdfinfo_main source/tools/pdfinfo.c:1041
    #11 0x403aa5 in main source/tools/mutool.c:127
    #12 0x7f7c92294f69 in __libc_start_main (/usr/lib/libc.so.6+0x20f69)

SUMMARY: AddressSanitizer: heap-buffer-overflow source/pdf/pdf-xref.c:211 in ensure_solid_xref
Shadow bytes around the buggy address:
  0x0c087fff8040: fa fa 00 00 00 00 00 fa fa fa 00 00 00 00 00 fa
  0x0c087fff8050: fa fa 00 00 00 00 00 fa fa fa 00 00 00 00 00 fa
  0x0c087fff8060: fa fa 00 00 00 00 00 fa fa fa 00 00 00 00 00 fa
  0x0c087fff8070: fa fa 00 00 00 00 00 fa fa fa 00 00 00 00 00 fa
  0x0c087fff8080: fa fa fd fd fd fd fd fa fa fa 00 00 00 00 00 fa
=>0x0c087fff8090: fa fa 00 00 00 00 00 fa fa fa 00 00 00 00 00[fa]
  0x0c087fff80a0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c087fff80b0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c087fff80c0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c087fff80d0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c087fff80e0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==7635==ABORTING
```

**Steps to reproduce invalid memory read issue (malformed input: [in2.pdf](mzet-adv-2017-01/in2.pdf)):**

```
$ ./mupdf-1.12-dest-asan/bin/mutool info in3.pdf
```

ASAN log:

```
==4144==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x0000006819ba bp 0x7ffec949c5b0 sp 0x7ffec949c560 T0)
==4144==The signal is caused by a READ memory access.
==4144==Hint: address points to the zero page.
    #0 0x6819b9 in ensure_solid_xref source/pdf/pdf-xref.c:211
    #1 0x686d6c in pdf_xref_find_subsection source/pdf/pdf-xref.c:825
    #2 0x6873a4 in pdf_read_old_xref source/pdf/pdf-xref.c:882
    #3 0x68916d in pdf_read_xref source/pdf/pdf-xref.c:1080
    #4 0x6896d3 in read_xref_section source/pdf/pdf-xref.c:1128
    #5 0x689d00 in pdf_read_xref_sections source/pdf/pdf-xref.c:1177
    #6 0x68a2a3 in pdf_load_xref source/pdf/pdf-xref.c:1233
    #7 0x68b807 in pdf_init_document source/pdf/pdf-xref.c:1371
    #8 0x6925b2 in pdf_open_document source/pdf/pdf-xref.c:2285
    #9 0x444ba5 in pdfinfo_info source/tools/pdfinfo.c:976
    #10 0x44538a in pdfinfo_main source/tools/pdfinfo.c:1041
    #11 0x403aa5 in main source/tools/mutool.c:127
    #12 0x7f360d36ff69 in __libc_start_main (/usr/lib/libc.so.6+0x20f69)
    #13 0x403339 in _start (/home/fuzz/mupdf-1.12-dest-asan/bin/mutool+0x403339)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV source/pdf/pdf-xref.c:211 in ensure_solid_xref
==4144==ABORTING
```

### Mitigation

Commit (from MuPdf master branch): [55c3f68d638ac1263a386e0aaa004bb6e8bde731](http://git.ghostscript.com/?p=mupdf.git;a=commit;h=55c3f68d638ac1263a386e0aaa004bb6e8bde731) fixes all three reported issues.

It is strongly recommended that users and distributors of MuPDF in version 1.12.0 rebuild their packages with this commit.

### Credits

Issues found and advisory written by Mariusz Ziulek.

### Timeline

- [ 18 Dec 2017 ] Issues reported ([1](https://bugs.ghostscript.com/show_bug.cgi?id=698819), [2](https://bugs.ghostscript.com/show_bug.cgi?id=698820), [3](https://bugs.ghostscript.com/show_bug.cgi?id=698821)) to the vendor
- [ 18 Dec 2017 ] Vendor respond that commit [55c3f68d638ac1263a386e0aaa004bb6e8bde731](http://git.ghostscript.com/?p=mupdf.git;a=commit;h=55c3f68d638ac1263a386e0aaa004bb6e8bde731) fixes these issues
- [ 22 Dec 2017 ] CVE number (CVE-2017-17858) assigned from MITRE
- [ 12 Jan 2018 ] Public release of this advisory
