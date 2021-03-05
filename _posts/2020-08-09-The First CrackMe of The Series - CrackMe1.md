---
title: The First CrackMe of The Series - CrackMe1
author: Fatih Çelik
date: 2020-08-09 11:33:00 +0800
categories: [Reverse Engineering,Crackme]
tags: [reverse engineering]     # TAG names should always be lowercase
---

- [1 - Starting The CrackMe Series - Why?](https://fatihhcelik.blogspot.com/2020/08/1-starting-crackme-series-why.html)
- 2 - The First CrackMe of The Series - CrackMe1 --> **You are here**

---

**Filename**: CrackMe1.exe

**Architecture**: x64

**Source**: [Github](https://github.com/fatihhcelik/MyCrackMes)

**MD5**: ACAB0D5D36D2780C173B8C76CEE1B2F3

**SHA-1**: F428776AEFCA26CF1C64175260FC8FA75D8CCCD9

---

Before go to the executable, you can find all of my crackmes in my [github](https://github.com/fatihhcelik/MyCrackMes) repository (you can see  in the header of the post as a source link) as an executable and source code. You can look at the source code of the challenge but it will give you spoiler so I don't recommend until the end of the post.

Most of the time, I will use [Ghidra](https://github.com/NationalSecurityAgency/ghidra) and [Radare2](https://github.com/radareorg/radare2) because they are free so you can reproduce the same steps with the same tools. But if you want to learn how to use Radare2, Ghidra or any tools in this post, I will not cover the usage of the tools right now. In addition to that, sometimes we can use the [IDA Freeware](https://www.hex-rays.com/products/ida/support/download_freeware/).

Firstly, I can use the "file" tool to get basic information from the executable.

```bash
$ file .\CrackMe1.exe
.\CrackMe1.exe; PE32+ executable for MS Windows (console) Mono/.Net assembly
```

In addition to that, we can use the "rabin2" from radare2.

![rabin2 usage](/photos/crackme-1-1.png)

I will open the Ghidra and look at the assembly code. I will not use decompiler window before look at the assembly version of the code. After understanding the code(or after failing to understand, i hope this will be not the case) I will look at the pseudocode.

Our executable is approximately 55K so finding the main function is pretty easy as you can see below.

![ghidra](/photos/crackme-1-2.png)

Before diving into all of the functions I will look at the function call graph to understand big picture.

![call graph](/photos/crackme-1-3.png)

As you can see above, executable probably consists of 3 important functions which are main -> read_from_file -> validate_license. After that, I will look at the graph view of the read_from_file and validate_license functions to understand their size.

*read_from_file,*

![call graph](/photos/crackme-1-4.png)

*validate_license,*

![](/photos/crackme-1-5.png)

I know they are not legible but don't worry I'll take a closer look at these graphs. As you can see above, my guess the heavy work is in the validate_license function probably this function is responsible more than one license control. Now, I will look at the assembly code of the main.

![](/photos/crackme-1-6.png)

As we know, firstly the prologue part is coming, after that the address of the "license.txt" string is copied to _Argc which is probably the label assigned by Ghidra to ECX register and this variable is the first argument of the read_from_file function. What we know until this step, there is a function named read_from_file and it want probably one argument which is the filename to read of its content. Let's look at the decompiler window of the main function.

![](/photos/crackme-1-7.png)

Now, I will go to the read_from_file function.

![](/photos/crackme-1-8.png)

As you can see from the graph, we should trace the green arrows to access **validate_license** function. Let's go to step by step from the first box. After the prologue, there are 2 things that catch my attention.

**00401583 LEA         RDX,[DAT_0040400c]**

**0040158a MOV       param_1,qword ptr [RBP + local_res8]**

**0040158e CALL      fopen**

*Signature of the fopen function,*

```c
FILE * fopen ( const char * filename, const char * mode );
```

Firstly, we see the [DAT_0040400c], this is probably the second argument of the fopen function because as a x64 Windows calling convention the first argument is copied to RCX and the second one to RDX. We know that the first argument of the fopen function is filename so param_1 is the name of the file to be read. As you can see above from the signature of the function, second argument is the mode. If we go to the address of the label DAT_0040400c, we can see the mode char variable. As you can see below, the file will be opened in read mode ("r"), this makes sense.

![](/photos/crackme-1-9.png)

**00401593 MOV    qword ptr [RBP + local_10],RAX**

**00401597 CMP     qword ptr [RBP + local_10],0x0**

**0040159c JNZ       LAB_004015b4**

After that, the return value of the fopen function will be stored at RAX register and compare with the 0x0 value. This is probably controlling the file's existence because fopen function return NULL if can't find the specified file. If the program can't find the file, prints the "Where is the file!" message to the console.

![](/photos/crackme-1-10.png)

So we will create the license.txt file to be able to bypass this.

![](/photos/crackme-1-11.png)

As you can see above, I created the license.txt and the error message is changed. So, now, we will analyze the LAB_004015b4 graph.

![](/photos/crackme-1-12.png)

*Signature of the fscanf function,*

```c
int fscanf(FILE *stream, const char *format, ...)
```

*Signature of the fclose function,*

```c
int fclose(FILE *stream)
```

What we know until here is we have to create license.txt file in the same directory with executable. Our new goal is go to the validate_license function. There is couple of interesting things in LAB_004015b4,

**004015b4 LEA       RDX=>local_78,[RBP + -0x70]**

**004015b8 MOV      RAX,qword ptr [RBP + local_10]**

**004015bc MOV      R8,RDX**

**004015bf LEA         RDX,[s_%[^_]_00404021]**

**004015c6 MOV       param_1,RAX**

**004015c9 CALL      fscanf**

Firstly, we know that function parameters will be stored at RCX,RDX and R8 if there is 3 parameters as a x64 Windows calling convention.

**RCX** --> Filename

**RDX** --> Format

**R8** --> Content of the file

You might be curious about what is format? If we go to the "**s_%[^_]_00404021"** label, we can learn the format specifier value.

![](/photos/crackme-1-13.png)

Format value is the "%[^\n]", this means **fscanf** function just reads the file's first line. (Until to the new line character which is \n) So we know that, license.txt file should have just one line in it.

**004015d5 CALL      fclose**

**004015da MOV       dword ptr [RBP + local_14],EAX**

**004015dd CMP       dword ptr [RBP + local_14],0x0**

**004015e1 JZ            LAB_004015f9**

After that, **fclose** function will try to close the opened file, if the return value of the **fclose** isn't 0x0, we will go to the validate_license function. So we will go to the LAB_004015f9,

**004015f9 LEA          RAX=>local_78,[RBP + -0x70]**

**004015fd MOV        param_1,RAX**

**00401600 CALL      validate_license**

[RBP+-0x70] kept the content of the file because R8 register pointed to that location. So, validate_license function will be called with just one parameter which is the content of the file.(content of the file = license key) This is the decompiler view of the read_from_file function, if you want to look at it. (Obviously, I replaced some of the variable names with their meaningful equivalents.)

![](/photos/crackme-1-14.png)

Yeah, if you remember the graph view of the validate_license function, it may seem scary. Let's look at it step by step.

![](/photos/crackme-1-15.png)

*Signature of the strlen function,*

```c
size_t strlen(const char *str)
```

We see some strings and 2 strlen function call in validate_license function.

**00401646 MOV       param_1,qword ptr [RBP]=>local_res8**

**0040164a CALL      strlen**

**0040164f MOV       dword ptr [RBP + local_4c],EAX**

**param_1** is the license key read from the license.txt file. First strlen function gets the length of the license key and stores it in [RBP+local_4c].

**0040164f MOV        dword ptr [RBP + local_4c],EAX**

**00401652 MOV       dword ptr [RBP + local_1c],0x0**

**00401659 MOV       param_1,qword ptr [RBP]=>local_res8**

**0040165d CALL      strlen**

**00401662 CMP        RAX,0x17**

**00401666 JZ            LAB_0040167e**

After that, strlen function is called again with the same parameter(actually there was no need to do this, this could use the [RBP+local_4c] value but nevermind :) and gets the length of the license key. After that compares the license key with the 0x17 which is  23. So, we learn that the license key should be 23 character length.

![](/photos/crackme-1-16.png)

To summarize the 4 graphs above, program take the first 7 bytes of the license key and compares with "#BEGIN#" one by one. So, we know that the license key should be started with #BEGIN# string. After this point, it will be very difficult to explain code with graph view due to the excessive amount of graphics so I will be using the decompiler view.

```c
void validate_license(char *key)
{
  size_t length;
  ulonglong uVar1;
  char key_temp [10];
  int _length;
  char *end;
  char *begin;
  char *encoded;
  int _counter;
  int local_28;
  int reverse_counter;
  int counter;
  int another_counter;

  encoded = "QnhjsxjYj}y";
  begin = "#BEGIN#";
  end = "#END#";

  length = strlen(key);
  _length = (int)length;
  another_counter = 0;
  length = strlen(key);

  if (length != 0x17) {
    printf("The license key is not correct.");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }

  counter = 0;
  while (counter < 7) {
    if (begin[counter] != key[counter]) {
      printf("The license key is not correct.");
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    counter = counter + 1;
  }

  reverse_counter = _length + -5;
  while (reverse_counter < _length) {
    if (end[another_counter] != key[reverse_counter]) {
      printf("The license key is not correct.");
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    another_counter = another_counter + 1;
    reverse_counter = reverse_counter + 1;
  }
  another_counter = 0;
  local_28 = 7;
  while (local_28 < 0x12) {
    key_temp[another_counter] = key[local_28];
    another_counter = another_counter + 1;
    local_28 = local_28 + 1;
  }

  _counter = 0;
  while( true ) {
    uVar1 = SEXT48(_counter);
    length = strlen(encoded);
    if (length <= uVar1) {
      printf("Congratz!");
      return;
    }
    if ((int)encoded[_counter] != (int)key_temp[_counter] + 5) break;
    _counter = _counter + 1;
  }
  printf("The license key is not correct.");
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```

I replaced some of the variable names with the more appropriate ones. (sorry for the bad namings :)

After controls the beginning of the license key, program controls the end of the key with "#END#" string. So, we know that license key will start with "#BEGIN#" and end with "#END#".

![](/photos/crackme-1-17.png)

As a result, program decodes the encoded string substracting 5 from their ascii value.

![](/photos/crackme-1-18.png)

So, I can write the python code just gives us the license key like below.

```python
encoded = "QnhjsxjYj}y"
end = "#END#"
license_key = "#BEGIN#"
for i in encoded:
    license_key += chr(ord(i)-5)

license_key += end
print(license_key)
```

The key is,

![](/photos/crackme-1-19.png)

So, I will put this string into the license.txt.

![](/photos/crackme-1-20.png)
