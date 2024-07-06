FROM ubuntu:24.04

RUN apt update && apt install -y strace gdb binutils less

COPY ./bphage.elf /bphage.elf

CMD /bphage.elf
