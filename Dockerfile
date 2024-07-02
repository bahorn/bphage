FROM ubuntu:22.04

# RUN apt update && apt install -y strace gdb elfutils

COPY ./dynamo-raw.elf /dynamo.elf

CMD /dynamo.elf
