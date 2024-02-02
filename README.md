# CPU Assembler
This assembler is designed to translate assembly language programs written for a custom CPU architecture into binary instructions that the CPU can execute. It's written in C for performance and compatibility with various operating systems.

## Features
- ### Assembly to Binary Translation: Converts custom assembly language instructions into binary format

## Getting started
### Prerequisites
- GCC (GNU Compiler) or any C compiler

## Installation
1. Clone the repository
```
git clone https://github.com/miguel-merlin/assembler.git
```
2. Navigate to the project directory
```
cd assembler
```
3. Compile the source code
```
gcc -o assembler assembler.c
```

## Usage
1. Create a custom assembly program
2. To assemble a program, run the assembler with the input assembly file.
```
./assembler <filename>
```

The assembler will generate a file ```output.txt``` with the binart instructions

## Licence
This project is licensed under the MIT Licence - see the `LICENSE` file for detail.
