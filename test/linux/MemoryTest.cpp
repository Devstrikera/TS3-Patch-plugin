#include <assert.h>
#include <iostream>
#include <cstring>
#include "include/process/process.h"
#include "include/process/pattern.h"

using namespace std;
const char* message = "Hello World. Message: XXX";

void injectMe() {
	printf("I got injected!\n");
}

void doStuff() {
	cout << "Hello World" << endl;
}

void makeJump() {
	auto memory = malloc(100);
}

char* make_jump(uintptr_t target, int length) {
	/*
	u_char* buffer = new u_char[]{
			0x50, 0x48,                             //pushq %rax
			0x8d, 0x05, 0x00, 0x00, 0x00, 0x00,     //leaq (%rip), %rax
			0x48, 0x83, 0xc0, 0x0f,                 //addq $0xF, %rax
			0x50,                                   //pushq %rax
			0x68, (target >> 0) & 0xFF, (target >> 8) & 0xFF, (target >> 16) & 0xFF, (target >> 24) & 0xFF, //pushq $0x401253 //TODO may 64bit?

	};
	*/
}

int main() {
//	auto process = process::self();
//	assert(process && process->valid() && process->running()); //Own process must be resolveable
//	process->parseMemoryRegions();

//	auto address = mem::find_pattern(process, "Hello World. Message: ");
//	assert((void*) address == (void*) message);

	__asm__("movq $0xFFFFF00F, %rax");
	__asm__("jmp %rax");
	__asm__("call %rax");

	__asm__("pushq %rax");
	__asm__("leaq (%rip), %rax");
	__asm__("addq $0xF, %rax");
	__asm__("pushq %rax");
	__asm__("pushq $0x401253");

	__asm__("leaq (__main), %rax");
	__asm__("jmpq %rax");
	__asm__("popq %rax");

	doStuff();

	uintptr_t doStuff = *&doStuff;
	return 0;
}