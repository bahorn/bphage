build:
	# not doing a custom header yet
	nasm -f elf64 -o src/dynamo.o src/dynamo.asm
	ld -m elf_x86_64 -s -o dynamo.elf src/dynamo.o
