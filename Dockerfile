FROM fedora:latest

# RUN apt update && apt install -y strace gdb elfutils

COPY ./bphage.elf /bphage.elf

CMD /bphage.elf
