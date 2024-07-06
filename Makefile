build_raw:
	nasm -f bin -o bphage.elf src/bphage.asm
	chmod +x ./bphage.elf

build_docker: build_raw
	docker build -t bahorn/dynamo-test .
	docker run -ti bahorn/dynamo-test bash
