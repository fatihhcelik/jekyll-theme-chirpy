---
title: NULL Pointer Dereference | Deark
author: Fatih Çelik
date: 2021-03-15 11:34:00 +0800
categories: [Vulnerability Research]
tags: [vulnerability research]
math: true
mermaid: true
---

**Software**: [https://github.com/jsummers/deark/](https://github.com/jsummers/deark/)

**Version**: 1.5.7-1

**Vulnerability**: NULL Pointer Dereference

**CVE**: N/A

**Description of the product:**

> A utility for file format and metadata analysis, data extraction, decompression, and image format decoding.

**Summary:**

An issue was discovered in Deark v1.5.7-1. A specially crafted input file can cause a NULL pointer dereference in dbuf_write function (src/deark-dbuf.c:1376). 

**Fix:**

[https://github.com/jsummers/deark/commit/287f5ac31dfdc074669182f51ece637706070eeb](https://github.com/jsummers/deark/commit/287f5ac31dfdc074669182f51ece637706070eeb)
