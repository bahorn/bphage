build:
	# not doing a custom header yet
	nasm -f elf64 -o src/dynamo.o src/dynamo.asm
	ld -m elf_x86_64 -s -o dynamo.elf src/dynamo.o

build_raw:
	nasm -f bin -o dynamo-raw.elf src/dynamo_raw.asm
	chmod +x ./dynamo-raw.elf
