---
title: Division By Zero | Deark
author: Fatih Çelik
date: 2021-03-15 11:33:00 +0800
categories: [Vulnerability Research]
tags: [vulnerability research]
math: true
mermaid: true
---

**Version**: 1.5.7-1

**Bug**: Division by Zero

**CVE**: N/A

**Description of the product:**

> A utility for file format and metadata analysis, data extraction, decompression, and image format decoding.

**Summary:**

An issue was discovered in Deark v1.5.7-1. A specially crafted input file can cause a division by zero in  (**src/fmtutil.c: 1621)** because of the value of bi→pixelsize.

**Fix:**

[https://github.com/jsummers/deark/commit/62acb7753b0e3c0d3ab3c15057b0a65222313334](https://github.com/jsummers/deark/commit/62acb7753b0e3c0d3ab3c15057b0a65222313334)
